using System.Text.Json;
using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Archiving;

namespace Mrbr.Bastion.Cache;

public sealed partial class DurableTelemetryCache
{
    private sealed record ArchiveState(long Sequence, string BlockHash, string ManifestHash, long PayloadBytes, long FileBytes, long Segments)
    {
        public static ArchiveState Empty => new(0, LedgerProtocol.GenesisHash, LedgerProtocol.GenesisHash, 0, 0, 0);
    }
    private readonly SemaphoreSlim _retentionGate = new(1, 1);
    private readonly object _leaseGate = new();
    private readonly Dictionary<string, ArchiveLease> _leases = [];
    private string _archiveDirectory;
    private ArchiveState? _knownArchiveState;
    private string? _lastRetentionError;

    private void EnsureArchiveSchema()
    {
        using var tx = _connection.BeginTransaction();
        RejectUnexpectedSchema(tx);
        using var q = Command("""
            CREATE TABLE IF NOT EXISTS cache_archive_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, sequence INTEGER NOT NULL,
                block_hash TEXT NOT NULL, manifest_hash TEXT NOT NULL, payload_bytes INTEGER NOT NULL, file_bytes INTEGER NOT NULL, segments INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS cache_archives (
                first_sequence INTEGER PRIMARY KEY, last_sequence INTEGER NOT NULL UNIQUE, file_name TEXT NOT NULL UNIQUE,
                manifest BLOB NOT NULL, file_bytes INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS cache_archive_location (singleton INTEGER PRIMARY KEY CHECK(singleton=1), path TEXT NOT NULL);
            INSERT OR IGNORE INTO cache_archive_state VALUES(1,1,0,$genesis,$genesis,0,0,0);
            """, tx, ("$genesis", LedgerProtocol.GenesisHash));
        q.ExecuteNonQuery();
        if (string.IsNullOrWhiteSpace(_options.Retention.ArchiveDirectory))
        {
            using var location = Command("SELECT path FROM cache_archive_location WHERE singleton=1",tx);
            if (location.ExecuteScalar() is string path)
            {
                if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException("Invalid recorded archive directory.");
                _archiveDirectory = path;
            }
        }
        tx.Commit();
    }
    private void RejectUnexpectedSchema(SqliteTransaction tx)
    {
        using (var triggers=Command("SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger'",tx))
            if(Convert.ToInt64(triggers.ExecuteScalar())!=0)throw new InvalidDataException("Unexpected executable triggers in the cache schema.");
        // Cascades must not turn an exact settled-row deletion into deletion of other evidence.
        foreach(string table in new[]{"ledger","blocks","cache_archives","cache_archive_state","cache_archive_location"})
        {
            using var keys=Command("PRAGMA foreign_key_list("+table+")",tx);using var rows=keys.ExecuteReader();
            if(rows.Read())throw new InvalidDataException("Unexpected foreign keys in the owned cache schema.");
        }
    }
    private ArchiveState ReadArchiveState(SqliteTransaction tx)
    {
        using var q = Command("SELECT version,sequence,block_hash,manifest_hash,payload_bytes,file_bytes,segments FROM cache_archive_state WHERE singleton=1", tx);
        using var r = q.ExecuteReader();
        if (!r.Read() || r.GetInt32(0) != 1) throw new InvalidDataException("Unsupported or missing cache archive state.");
        var state = new ArchiveState(r.GetInt64(1), r.GetString(2), r.GetString(3), r.GetInt64(4), r.GetInt64(5), r.GetInt64(6));
        if (state.Sequence < 0 || state.PayloadBytes < 0 || state.FileBytes < 0 || state.Segments < 0
            || state.Sequence == 0 && state != ArchiveState.Empty || _knownArchiveState is not null && state != _knownArchiveState)
            throw new InvalidDataException("Cache archive state changed outside its writer or is inconsistent.");
        return state;
    }
    private List<ArchiveSegment> ReadCatalog(SqliteTransaction tx)
    {
        using var q = Command("SELECT first_sequence,last_sequence,file_name,manifest,file_bytes FROM cache_archives ORDER BY first_sequence", tx);
        using var r = q.ExecuteReader(); var result = new List<ArchiveSegment>();
        while (r.Read())
        {
            var manifest = ArchiveProtocol.Decode<SignedArchiveManifest>(ReadBoundedBlob(r, 3, ArchiveProtocol.MaximumManifestBytes));
            ArchiveProtocol.VerifyManifest(manifest, _blockVerifier); var c = manifest.Content;
            if (c.NodeId != _options.NodeId || c.LedgerId != _ledgerId || c.FirstSequence != r.GetInt64(0)
                || c.LastSequence != r.GetInt64(1) || r.GetString(2) != ArchiveProtocol.FileName(c.ArchiveId)
                || r.GetInt64(4) < 24 || r.GetInt64(4) > ArchiveProtocol.MaximumFileBytes)
                throw new InvalidDataException("Archive catalog identity mismatch.");
            result.Add(new(r.GetString(2), r.GetInt64(4), manifest));
        }
        return result;
    }
    private static void VerifyCatalog(List<ArchiveSegment> segments, ArchiveState expected)
    {
        var state = ArchiveState.Empty;
        foreach (var segment in segments)
        {
            var c = segment.Manifest.Content;
            if (c.FirstSequence != checked(state.Sequence + 1) || c.PreviousBlockHash != state.BlockHash || c.PreviousArchiveHash != state.ManifestHash)
                throw new InvalidDataException("Archive catalog has a gap, reorder or broken hash chain.");
            state = new(c.LastSequence, c.TailBlockHash, segment.Manifest.ManifestHash, checked(state.PayloadBytes + c.PayloadBytes),
                checked(state.FileBytes + segment.FileBytes), state.Segments + 1);
        }
        if (state != expected) throw new InvalidDataException("Archive catalog does not match its retained head.");
    }
    private ArchiveSegment VerifySegment(ArchiveSegment segment, Action<VerifiedArchiveEntry>? observe, CancellationToken ct, bool deep = true)
    {
        try
        {
            string path = Path.Combine(_archiveDirectory, segment.FileName);
            void Inspect(VerifiedArchiveEntry row)
            {
                if (row.Block.Content.Payload.Length > _options.MaximumPayloadBytes || row.Block.Content.EventCount > _options.MaximumEventsPerBlock)
                    throw new InvalidDataException("Archived block exceeds this cache's configured limits.");
                observe?.Invoke(row);
            }
            ArchiveSegment actual;
            if (OperatingSystem.IsWindows())
            {
                ArchiveLease lease;
                lock (_leaseGate)
                {
                    if (!_leases.TryGetValue(segment.Manifest.ManifestHash, out lease!))
                    {
                        lease = ArchiveFile.OpenVerified(path, _blockVerifier, _receiptVerifier, _options.AdditionalPayloadCodecs, ct);
                        _leases.Add(segment.Manifest.ManifestHash, lease);
                    }
                }
                lease.VerifyPath();
                actual = deep || observe is not null ? lease.Reverify(_blockVerifier, _receiptVerifier, _options.AdditionalPayloadCodecs, Inspect, ct) : lease.Segment;
            }
            else actual = ArchiveFile.Verify(path, _blockVerifier, _receiptVerifier, _options.AdditionalPayloadCodecs, Inspect, ct);
            if (actual.Manifest.ManifestHash != segment.Manifest.ManifestHash || actual.FileBytes != segment.FileBytes)
                throw new InvalidDataException("Archive file differs from its committed catalog proof.");
            return actual;
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException or EndOfStreamException)
        { throw new InvalidDataException("Required cache archive history is missing.", error); }
    }
    public async Task<CacheStorageStatus> GetStorageStatusAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try { using var tx = _connection.BeginTransaction(deferred: true); return ReadStorage(tx); }
        finally { _gate.Release(); }
    }
    public async Task<ArchiveSegment[]> GetArchivesAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(deferred: true); _ = ReadCheckpoint(tx);
            var catalog = ReadCatalog(tx); VerifyCatalog(catalog, ReadArchiveState(tx)); return catalog.ToArray();
        }
        finally { _gate.Release(); }
    }
    private CacheStorageStatus ReadStorage(SqliteTransaction tx)
    {
        _ = ReadCheckpoint(tx); var state = ReadArchiveState(tx);
        using var q = Command("SELECT COUNT(*),COALESCE(SUM(payload_bytes),0) FROM blocks", tx); using var r = q.ExecuteReader(); r.Read();
        return new(r.GetInt64(0), r.GetInt64(1), state.Sequence, state.PayloadBytes, state.FileBytes, state.Segments, _archiveDirectory, Volatile.Read(ref _lastRetentionError));
    }
    /// <summary>Archives a bounded, eligible settled prefix. All file proofs precede the atomic resident deletion/catalog commit.</summary>
    public async Task<CacheRetentionResult> ApplyRetentionAsync(CancellationToken cancellationToken = default)
    {
        await _retentionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            long blocks = 0, bytes = 0, segments = 0;
            if (_options.Retention.Enabled)
                for (int i = 0; i < _options.Retention.MaximumSegmentsPerRun; i++)
                {
                    var segment = await ArchiveNextAsync(cancellationToken).ConfigureAwait(false);
                    if (segment is null) break;
                    blocks += segment.Manifest.Content.LastSequence - segment.Manifest.Content.FirstSequence + 1;
                    bytes += segment.Manifest.Content.PayloadBytes; segments++;
                }
            Volatile.Write(ref _lastRetentionError, null);
            return new(blocks, bytes, segments, await GetStorageStatusAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) { Volatile.Write(ref _lastRetentionError, error.Message); throw; }
        finally { _retentionGate.Release(); }
    }
    private async Task<ArchiveSegment?> ArchiveNextAsync(CancellationToken ct)
    {
        var p = _options.Retention; ArchiveState previous; LedgerCheckpoint head;
        using var snapshot = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _options.DatabasePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        snapshot.Open(); using var read = snapshot.BeginTransaction(deferred: true);
        await EnterAsync(ct).ConfigureAwait(false);
        try { head = ReadCheckpoint(read); previous = ReadArchiveState(read); }
        finally { _gate.Release(); }
        long upper = head.SequenceNumber - p.KeepRecentBlocks;
        if (upper <= previous.Sequence) return null;
        long fileLimit = p.MaximumSegmentFileBytes;
        if (p.MaximumArchiveBytes > 0)
        {
            long existing = Directory.Exists(_archiveDirectory) ? Directory.EnumerateFiles(_archiveDirectory, "*.bastion-archive").Sum(path => new FileInfo(path).Length) : 0;
            fileLimit = Math.Min(fileLimit, p.MaximumArchiveBytes - existing);
            if (fileLimit < 262144) throw new IOException("Cache archive quota reached. Resident evidence was preserved.");
        }
        DateTimeOffset cutoff = _options.TimeProvider.GetUtcNow().AddSeconds(-p.MinimumAgeSeconds);
        IEnumerable<ArchiveEntry> Eligible()
        {
            using var q = Command("SELECT sequence,block_id,body,payload_bytes,receipt FROM blocks WHERE sequence<=$upper ORDER BY sequence LIMIT $limit", read,
                ("$upper", upper), ("$limit", p.MaximumBlocksPerSegment));
            using var r = q.ExecuteReader(); long next = previous.Sequence + 1, payload = 0, fileBytes = 8 + ArchiveProtocol.MaximumManifestBytes + 12;
            while (r.Read())
            {
                ct.ThrowIfCancellationRequested();
                if (r.GetInt64(0) != next) throw new InvalidDataException("Resident prefix is not contiguous with archived history.");
                if (r.IsDBNull(4)) yield break; // Never cross an unsettled gap, even if later blocks have receipts.
                var block = ReadVerifiedBlock(r);
                var entry = new ArchiveEntry(ReadBoundedBlob(r, 2, ArchiveProtocol.MaximumBodyBytes), ReadBoundedBlob(r, 4, TelemetryJson.MaximumReceiptBytes));
                var verified = ArchiveProtocol.VerifyEntry(entry, _blockVerifier, _receiptVerifier, _options.AdditionalPayloadCodecs);
                if (block.Content.CreatedUtc > cutoff || verified.Receipt.Content.AcceptedUtc > cutoff) yield break;
                long size = 8L + entry.BlockJson.Length + entry.ReceiptJson.Length;
                if (payload + block.Content.Payload.Length > p.MaximumSegmentPayloadBytes || fileBytes + size > fileLimit)
                {
                    if (next == previous.Sequence + 1) throw new IOException("The next settled block does not fit the archive segment/quota limits. Resident evidence was preserved.");
                    yield break;
                }
                payload += block.Content.Payload.Length; fileBytes += size; next++; yield return entry;
            }
        }
        using var eligible = Eligible().GetEnumerator();
        if (!eligible.MoveNext()) return null;
        IEnumerable<ArchiveEntry> Entries() { do { yield return eligible.Current; } while (eligible.MoveNext()); }
        var segment = ArchiveFile.Create(_archiveDirectory, Entries(), previous.ManifestHash, _signer, _blockVerifier, _receiptVerifier,
            _options.AdditionalPayloadCodecs, fileLimit, ct);
        // End the read snapshot before pruning; ongoing heartbeat snapshots remain independent.
        eligible.Dispose(); read.Dispose();
        bool committed = false;
        try
        {
        VerifySegment(segment, null, ct, deep: false);
        _options.RetentionProbe?.Invoke(RetentionStage.ArchiveFlushed);
        await EnterAsync(ct).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(); _ = ReadCheckpoint(tx); RejectUnexpectedSchema(tx);
            if (ReadArchiveState(tx) != previous) throw new InvalidDataException("Archive head changed during preparation.");
            long deleted = 0;
            VerifySegment(segment, row =>
            {
                using var remove = Command("DELETE FROM blocks WHERE sequence=$seq AND body=$body AND receipt=$receipt", tx,
                    ("$seq", row.Block.Content.SequenceNumber), ("$body", row.BlockJson), ("$receipt", row.ReceiptJson));
                if (remove.ExecuteNonQuery() != 1) throw new InvalidDataException("Resident archive candidate changed; pruning was rolled back.");
                deleted++;
            }, ct);
            var c = segment.Manifest.Content;
            if (deleted != c.LastSequence - c.FirstSequence + 1) throw new InvalidDataException("Archive prune count mismatch.");
            using (var insert = Command("INSERT INTO cache_archives VALUES($first,$last,$file,$manifest,$bytes)", tx,
                ("$first", c.FirstSequence), ("$last", c.LastSequence), ("$file", segment.FileName),
                ("$manifest", JsonSerializer.SerializeToUtf8Bytes(segment.Manifest, ArchiveProtocol.Json)), ("$bytes", segment.FileBytes))) insert.ExecuteNonQuery();
            using (var location=Command("INSERT INTO cache_archive_location VALUES(1,$path) ON CONFLICT(singleton) DO UPDATE SET path=excluded.path",tx,("$path",_archiveDirectory))) location.ExecuteNonQuery();
            var state = new ArchiveState(c.LastSequence, c.TailBlockHash, segment.Manifest.ManifestHash, checked(previous.PayloadBytes + c.PayloadBytes),
                checked(previous.FileBytes + segment.FileBytes), previous.Segments + 1);
            using (var update = Command("UPDATE cache_archive_state SET sequence=$seq,block_hash=$block,manifest_hash=$manifest,payload_bytes=$payload,file_bytes=$file,segments=$segments WHERE singleton=1", tx,
                ("$seq", state.Sequence), ("$block", state.BlockHash), ("$manifest", state.ManifestHash), ("$payload", state.PayloadBytes),
                ("$file", state.FileBytes), ("$segments", state.Segments))) update.ExecuteNonQuery();
            ct.ThrowIfCancellationRequested(); _options.RetentionProbe?.Invoke(RetentionStage.BeforePruneCommit);
            tx.Commit(); _knownArchiveState = state; committed = true; _options.RetentionProbe?.Invoke(RetentionStage.AfterPruneCommit);
            return segment;
        }
        finally { _gate.Release(); }
        }
        catch
        {
            if (!committed) lock (_leaseGate) { if (_leases.Remove(segment.Manifest.ManifestHash, out var lease)) lease.Dispose(); }
            throw;
        }
    }

    public async Task RunRetentionAsync(Action<string>? report, CancellationToken cancellationToken)
    {
        if (!_options.Retention.Enabled) return;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try { var result = await ApplyRetentionAsync(cancellationToken).ConfigureAwait(false); if (result.ArchivedBlocks > 0) report?.Invoke($"Archived {result.ArchivedBlocks} settled blocks; resident payload={result.Storage.ResidentPayloadBytes}; archive files={result.Storage.ArchiveFileBytes}."); }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                { report?.Invoke("Cache retention failed; evidence preserved: " + error.Message); }
                await Task.Delay(TimeSpan.FromSeconds(_options.Retention.IntervalSeconds), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }
    /// <summary>Explicit stopped-host maintenance: verifies history, checkpoints WAL and vacuums reusable pages back to the filesystem.</summary>
    public async Task CompactAsync(CancellationToken cancellationToken = default)
    {
        await VerifyIntegrityAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        await _retentionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _auditGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await EnterAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    void Checkpoint()
                    {
                        using var checkpoint = _connection.CreateCommand(); checkpoint.CommandText="PRAGMA wal_checkpoint(TRUNCATE)";
                        using var result=checkpoint.ExecuteReader();
                        if(!result.Read() || result.GetInt32(0)!=0)throw new IOException("WAL compaction is blocked by another reader. Stop external readers and retry; history was preserved.");
                    }
                    cancellationToken.ThrowIfCancellationRequested(); Checkpoint();
                    using var vacuum = _connection.CreateCommand(); vacuum.CommandText = "VACUUM"; vacuum.ExecuteNonQuery(); Checkpoint();
                }
                finally { _gate.Release(); }
            }
            finally { _auditGate.Release(); }
        }
        finally { _retentionGate.Release(); }
    }
}
