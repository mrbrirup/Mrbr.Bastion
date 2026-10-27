using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Archiving;

namespace Mrbr.Bastion.Cache;

/// <summary>
/// A single-writer SQLite outbox. Blocks, chain state, and receipt transitions commit atomically
/// with synchronous=FULL. Settled blocks remain available for verification; no evidence is auto-purged.
/// </summary>
public sealed partial class DurableTelemetryCache : IAuditableTelemetryCache
{
    // Keep hot metadata queries on small covering indexes, away from signed payload/receipt BLOBs.
    internal const string StoredBytesSql = "SELECT COALESCE(SUM(payload_bytes),0) FROM blocks";
    internal const string StatusSql = """
        SELECT (SELECT COUNT(*) FROM blocks WHERE receipt IS NULL),
               (SELECT COALESCE(SUM(payload_bytes),0) FROM blocks WHERE receipt IS NULL),
               (SELECT COALESCE(SUM(payload_bytes),0) FROM blocks)
        """;
    private readonly DurableCacheOptions _options;
    private readonly ISignatureSigner _signer;
    private readonly ISignatureVerifier _blockVerifier;
    private readonly ISignatureVerifier _receiptVerifier;
    private readonly SqliteConnection _connection;
    private readonly FileStream _writerLock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SemaphoreSlim _auditGate = new(1, 1);
    private readonly Guid _ledgerId;
    private LedgerCheckpoint? _lastKnownCheckpoint;
    private bool _disposed;

    private DurableTelemetryCache(DurableCacheOptions options, ISignatureSigner signer,
        ISignatureVerifier blockVerifier, ISignatureVerifier receiptVerifier,
        SqliteConnection connection, FileStream writerLock, Guid ledgerId)
    {
        _options = options;
        _signer = signer;
        _blockVerifier = blockVerifier;
        _receiptVerifier = receiptVerifier;
        _connection = connection;
        _writerLock = writerLock;
        _ledgerId = ledgerId;
        string archiveRoot = string.IsNullOrWhiteSpace(options.Retention.ArchiveDirectory) ? options.DatabasePath + ".archives"
            : Path.GetFullPath(options.Retention.ArchiveDirectory, Path.GetDirectoryName(options.DatabasePath)!);
        _archiveDirectory = Path.Combine(archiveRoot, ledgerId.ToString("N"));
    }

    /// <summary>
    /// Opens and fully verifies an existing ledger, or creates a new one. Trusted checkpoints must
    /// come from outside this database. Signing providers are owned and disposed by the caller.
    /// </summary>
    public static async Task<DurableTelemetryCache> OpenAsync(DurableCacheOptions options,
        ISignatureSigner signer, ISignatureVerifier blockVerifier, ISignatureVerifier receiptVerifier,
        LedgerCheckpoint? trustedCheckpoint = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(blockVerifier);
        ArgumentNullException.ThrowIfNull(receiptVerifier);
        options.Validate();
        cancellationToken.ThrowIfCancellationRequested();
        options = options with { DatabasePath = Path.GetFullPath(options.DatabasePath), Retention = options.Retention with { } };
        Directory.CreateDirectory(Path.GetDirectoryName(options.DatabasePath)!);
        var writerLock = new FileStream(options.DatabasePath + ".writer.lock", FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        SqliteConnection? connection = null;
        DurableTelemetryCache? cache = null;
        try
        {
            bool exists = File.Exists(options.DatabasePath);
            if (!exists && trustedCheckpoint is not null)
                throw new InvalidDataException("The externally anchored cache database is missing.");
            connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = options.DatabasePath,
                Mode = exists ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadWriteCreate,
                Pooling = false
            }.ToString());
            connection.Open();
            using (var setup = connection.CreateCommand())
            {
                setup.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;";
                setup.ExecuteNonQuery();
            }
            if (!exists) Initialize(connection, options.NodeId);
            Guid ledgerId;
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "SELECT ledger_id FROM ledger WHERE singleton=1";
                if (!Guid.TryParse(command.ExecuteScalar() as string, out ledgerId) || ledgerId == Guid.Empty)
                    throw new InvalidDataException("Missing or invalid ledger identity.");
            }
            cache = new DurableTelemetryCache(options, signer, blockVerifier, receiptVerifier, connection, writerLock, ledgerId);
            cache.EnsureArchiveSchema();
            await cache.VerifyIntegrityAsync(trustedCheckpoint, cancellationToken).ConfigureAwait(false);
            // Derived indexes also upgrade existing outboxes, after their retained evidence is verified.
            EnsureMetadataIndexes(connection);
            if (cache._knownArchiveState?.Sequence > 0)
            {
                using var tx=connection.BeginTransaction();cache.RejectUnexpectedSchema(tx);
                using var location=connection.CreateCommand();location.Transaction=tx;
                location.CommandText = "INSERT INTO cache_archive_location VALUES(1,$path) ON CONFLICT(singleton) DO UPDATE SET path=excluded.path";
                location.Parameters.AddWithValue("$path",cache._archiveDirectory); location.ExecuteNonQuery();
                tx.Commit();
            }
            return cache;
        }
        catch
        {
            if (cache is not null) await cache.DisposeAsync().ConfigureAwait(false);
            else
            {
                connection?.Dispose();
                writerLock.Dispose();
            }
            throw;
        }
    }

    public Task<SignedTelemetryBlock> AppendAsync(IReadOnlyList<TelemetryEvent> events,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(events);
        var snapshot = events.ToArray();
        if (snapshot.Length > _options.MaximumEventsPerBlock)
            throw new ArgumentOutOfRangeException(nameof(events), "The batch exceeds MaximumEventsPerBlock.");
        var payload = LedgerProtocol.SerializeEvents(snapshot);
        if (payload.Length > _options.MaximumPayloadBytes)
            throw new ArgumentOutOfRangeException(nameof(events), "The serialized batch exceeds MaximumPayloadBytes.");
        return AppendPayloadAsync(LedgerProtocol.PayloadFormat, payload, snapshot.Length, cancellationToken);
    }
    public async Task<SignedTelemetryBlock> AppendPayloadAsync(string format, ReadOnlyMemory<byte> bytes, int count, CancellationToken cancellationToken = default)
    {
        if (bytes.Length is < 1 || bytes.Length > _options.MaximumPayloadBytes || count is < 1 || count > _options.MaximumEventsPerBlock)
            throw new ArgumentOutOfRangeException(nameof(bytes));
        byte[] payload = bytes.ToArray();
        if (format != LedgerProtocol.PayloadFormat)
            (_options.AdditionalPayloadCodecs.SingleOrDefault(c => c.Format == format) ?? throw new InvalidDataException("Unsupported payload format.")).Validate(payload, count);
        else if (count < 1) throw new InvalidDataException("Empty event batch.");
        try { return await AppendCoreAsync(format, payload, count, _options.Retention.Enabled, cancellationToken).ConfigureAwait(false); }
        catch (RetentionNeededException)
        {
            await ApplyRetentionAsync(cancellationToken).ConfigureAwait(false);
            return await AppendCoreAsync(format, payload, count, false, cancellationToken).ConfigureAwait(false);
        }
    }
    private sealed class RetentionNeededException : Exception;
    private async Task<SignedTelemetryBlock> AppendCoreAsync(string format, byte[] payload, int count, bool allowRetention, CancellationToken cancellationToken)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var transaction = _connection.BeginTransaction();
            var checkpoint = ReadCheckpoint(transaction);
            VerifyTail(checkpoint, transaction);
            using (var size = Command(StoredBytesSql, transaction))
            {
                long stored = Convert.ToInt64(size.ExecuteScalar());
                if (stored > _options.MaximumStoredPayloadBytes - payload.Length)
                {
                    if (allowRetention) throw new RetentionNeededException();
                    throw new IOException("The cache payload capacity has been reached. No unsettled evidence was deleted.");
                }
            }
            var content = new TelemetryBlockContent(LedgerProtocol.Version, _options.NodeId, _ledgerId,
                Guid.NewGuid(), checked(checkpoint.SequenceNumber + 1), DateTimeOffset.UtcNow,
                checkpoint.BlockHash, format, count, _signer.Algorithm, _signer.KeyId, payload);
            var encoded = LedgerProtocol.EncodeBlock(content);
            var block = new SignedTelemetryBlock(content, Convert.ToHexString(SHA256.HashData(encoded)), _signer.Sign(encoded));
            BlockPayloadValidation.Validate(block, _options.AdditionalPayloadCodecs);
            if (!LedgerProtocol.VerifyBlock(block, _blockVerifier))
                throw new CryptographicException("The configured block verifier cannot verify the newly signed block.");
            using (var insert = Command("INSERT INTO blocks(sequence,block_id,body,payload_bytes) VALUES($seq,$id,$body,$size)",
                transaction, ("$seq", content.SequenceNumber), ("$id", content.BlockId.ToString("D")),
                ("$body", JsonSerializer.SerializeToUtf8Bytes(block)), ("$size", payload.Length)))
                insert.ExecuteNonQuery();
            using (var update = Command("UPDATE ledger SET last_sequence=$seq,tail_hash=$hash WHERE singleton=1",
                transaction, ("$seq", content.SequenceNumber), ("$hash", block.BlockHash)))
                update.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            _lastKnownCheckpoint = new LedgerCheckpoint(content.NodeId, content.LedgerId, content.SequenceNumber, block.BlockHash);
            return block;
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<SignedTelemetryBlock>> ReadPendingAsync(int maximumBlocks = 100,
        CancellationToken cancellationToken = default)
    {
        if (maximumBlocks is < 1 or > 10000) throw new ArgumentOutOfRangeException(nameof(maximumBlocks));
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var transaction = _connection.BeginTransaction(deferred: true);
            _ = ReadCheckpoint(transaction);
            using var command = Command("SELECT sequence,block_id,body,payload_bytes FROM blocks WHERE receipt IS NULL ORDER BY sequence LIMIT $limit",
                transaction, ("$limit", maximumBlocks));
            using var reader = command.ExecuteReader();
            var result = new List<SignedTelemetryBlock>();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.Add(ReadVerifiedBlock(reader));
            }
            return result;
        }
        finally { _gate.Release(); }
    }

    public async Task ReconcileAsync(SettlementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        // Snapshot mutable arrays before verification and persistence.
        receipt = receipt with { Signature = receipt.Signature?.ToArray()! };
        if (!LedgerProtocol.VerifyReceipt(receipt, _receiptVerifier))
            throw new CryptographicException("The settlement receipt signature or receiver key is invalid.");
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var transaction = _connection.BeginTransaction();
            _ = ReadCheckpoint(transaction);
            var archived = ReadArchiveState(transaction);
            if (receipt.Content.SequenceNumber <= archived.Sequence)
            {
                var segment = ReadCatalog(transaction).SingleOrDefault(s => s.Manifest.Content.FirstSequence <= receipt.Content.SequenceNumber
                    && s.Manifest.Content.LastSequence >= receipt.Content.SequenceNumber) ?? throw new InvalidDataException("Archived receipt range missing.");
                bool found = false;
                VerifySegment(segment, row => { if (row.Block.Content.SequenceNumber == receipt.Content.SequenceNumber) { MatchReceipt(receipt, row.Block); found = true; } }, cancellationToken);
                if (!found) throw new InvalidDataException("Archived receipt block missing.");
                return;
            }
            using (var select = Command("SELECT sequence,block_id,body,payload_bytes FROM blocks WHERE sequence=$seq",
                transaction, ("$seq", receipt.Content.SequenceNumber)))
            using (var reader = select.ExecuteReader())
            {
                if (!reader.Read()) throw new InvalidDataException("The receipt does not identify a retained block.");
                MatchReceipt(receipt, ReadVerifiedBlock(reader));
            }
            // Keep the first valid proof. A different valid receipt for the same exact block is an idempotent retry.
            using (var update = Command("UPDATE blocks SET receipt=COALESCE(receipt,$receipt) WHERE sequence=$seq",
                transaction, ("$receipt", JsonSerializer.SerializeToUtf8Bytes(receipt)), ("$seq", receipt.Content.SequenceNumber)))
                update.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
        }
        finally { _gate.Release(); }
    }

    public async Task VerifyIntegrityAsync(LedgerCheckpoint? trustedCheckpoint = null,
        CancellationToken cancellationToken = default) =>
        _ = await CaptureSnapshotAsync(trustedCheckpoint, cancellationToken, true).ConfigureAwait(false);

    public Task<CacheStatus> CaptureAuditSnapshotAsync(LedgerCheckpoint? trustedCheckpoint = null,
        CancellationToken cancellationToken = default) => CaptureSnapshotAsync(trustedCheckpoint, cancellationToken, false);

    private async Task<CacheStatus> CaptureSnapshotAsync(LedgerCheckpoint? trustedCheckpoint, CancellationToken cancellationToken, bool deepArchives)
    {
        // Serialize full audits/disposal, but let the WAL writer keep committing during verification.
        await _auditGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        SqliteConnection? snapshot = null;
        SqliteTransaction? transaction = null;
        try
        {
            LedgerCheckpoint checkpoint;
            ArchiveState archiveState;
            await EnterAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                snapshot = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = _options.DatabasePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
                snapshot.Open();
                using (var setup = snapshot.CreateCommand())
                { setup.CommandText = "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;"; setup.ExecuteNonQuery(); }
                transaction = snapshot.BeginTransaction(deferred: true);
                // The first read establishes the WAL snapshot while its tip still matches our writer.
                checkpoint = ReadCheckpoint(transaction);
                archiveState = ReadArchiveState(transaction);
            }
            finally { _gate.Release(); }
            using (var check = Command("PRAGMA quick_check", transaction))
            {
                if (!string.Equals(check.ExecuteScalar() as string, "ok", StringComparison.Ordinal))
                    throw new InvalidDataException("SQLite integrity verification failed.");
            }
            if (trustedCheckpoint is not null && (trustedCheckpoint.NodeId != _options.NodeId
                || trustedCheckpoint.LedgerId != _ledgerId || trustedCheckpoint.SequenceNumber < 0
                || trustedCheckpoint.SequenceNumber > checkpoint.SequenceNumber))
                throw new InvalidDataException("The cache is missing or behind the trusted external checkpoint.");
            long sequence = 0;
            long pending = 0, pendingBytes = 0, storedBytes = 0;
            string hash = LedgerProtocol.GenesisHash;
            bool anchorFound = trustedCheckpoint is null
                || (trustedCheckpoint.SequenceNumber == 0 && trustedCheckpoint.BlockHash == hash);
            var segments = ReadCatalog(transaction);
            VerifyCatalog(segments, archiveState);
            foreach (var segment in segments)
            {
                VerifySegment(segment, null, cancellationToken, deepArchives);
                var c = segment.Manifest.Content;
                if (c.FirstSequence != checked(sequence + 1) || c.PreviousBlockHash != hash)
                    throw new InvalidDataException("Archived history has a gap or broken predecessor.");
                if (trustedCheckpoint is { } anchor && anchor.SequenceNumber >= c.FirstSequence && anchor.SequenceNumber <= c.LastSequence)
                {
                    if (anchor.SequenceNumber == c.LastSequence) anchorFound = anchor.BlockHash == c.TailBlockHash;
                    else VerifySegment(segment, row => { if (row.Block.Content.SequenceNumber == anchor.SequenceNumber) anchorFound = row.Block.BlockHash == anchor.BlockHash; }, cancellationToken);
                }
                sequence = c.LastSequence; hash = c.TailBlockHash; storedBytes = checked(storedBytes + c.PayloadBytes);
            }
            using var command = Command("SELECT sequence,block_id,body,payload_bytes,receipt FROM blocks ORDER BY sequence", transaction);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var block = ReadVerifiedBlock(reader);
                storedBytes = checked(storedBytes + block.Content.Payload.Length);
                if (block.Content.SequenceNumber != checked(sequence + 1) || block.Content.PreviousBlockHash != hash)
                    throw new InvalidDataException("The ledger has a sequence gap or broken hash chain.");
                sequence = block.Content.SequenceNumber;
                hash = block.BlockHash;
                if (trustedCheckpoint?.SequenceNumber == sequence)
                    anchorFound = trustedCheckpoint.BlockHash == hash;
                if (!reader.IsDBNull(4))
                {
                    var receipt = Decode<SettlementReceipt>(ReadBoundedBlob(reader, 4, 128 * 1024));
                    if (!LedgerProtocol.VerifyReceipt(receipt, _receiptVerifier))
                        throw new InvalidDataException("A stored settlement receipt failed verification.");
                    MatchReceipt(receipt, block);
                }
                else
                {
                    pending++;
                    pendingBytes = checked(pendingBytes + block.Content.Payload.Length);
                }
            }
            if (checkpoint.SequenceNumber != sequence || checkpoint.BlockHash != hash || !anchorFound)
                throw new InvalidDataException("The chain tip or trusted checkpoint does not match retained evidence.");
            await EnterAsync(cancellationToken).ConfigureAwait(false);
            try { _lastKnownCheckpoint ??= checkpoint; _knownArchiveState ??= archiveState; } // Never rewind the writer to an older audit snapshot.
            finally { _gate.Release(); }
            return new CacheStatus(checkpoint, pending, pendingBytes, storedBytes);
        }
        finally
        {
            transaction?.Dispose(); snapshot?.Dispose();
            _auditGate.Release();
        }
    }

    public async Task<CacheStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var transaction = _connection.BeginTransaction(deferred: true);
            var checkpoint = ReadCheckpoint(transaction);
            var archived = ReadArchiveState(transaction);
            using var command = Command(StatusSql, transaction);
            using var reader = command.ExecuteReader();
            reader.Read();
            return new CacheStatus(checkpoint, reader.GetInt64(0), reader.GetInt64(1), checked(reader.GetInt64(2) + archived.PayloadBytes));
        }
        finally { _gate.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        await _retentionGate.WaitAsync().ConfigureAwait(false);
        try
        {
        await _auditGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_disposed) return;
                _disposed = true;
                lock (_leaseGate) { foreach (var lease in _leases.Values) lease.Dispose(); _leases.Clear(); }
                try { _connection.Dispose(); }
                finally { _writerLock.Dispose(); }
            }
            finally { _gate.Release(); }
        }
        finally { _auditGate.Release(); }
        }
        finally { _retentionGate.Release(); }
    }

    private async Task EnterAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (_disposed)
        {
            _gate.Release();
            throw new ObjectDisposedException(nameof(DurableTelemetryCache));
        }
    }

    private LedgerCheckpoint ReadCheckpoint(SqliteTransaction transaction)
    {
        using var command = Command("SELECT version,node_id,ledger_id,last_sequence,tail_hash FROM ledger WHERE singleton=1", transaction);
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetInt32(0) != LedgerProtocol.Version || reader.GetString(1) != _options.NodeId
            || reader.GetString(2) != _ledgerId.ToString("D") || reader.GetInt64(3) < 0)
            throw new InvalidDataException("The ledger metadata does not match the configured node and ledger.");
        var checkpoint = new LedgerCheckpoint(_options.NodeId, _ledgerId, reader.GetInt64(3), reader.GetString(4));
        _ = ReadArchiveState(transaction);
        if (_lastKnownCheckpoint is not null && checkpoint != _lastKnownCheckpoint)
            throw new InvalidDataException("The chain tip changed outside this cache writer.");
        return checkpoint;
    }

    private void VerifyTail(LedgerCheckpoint checkpoint, SqliteTransaction transaction)
    {
        using var command = Command("SELECT sequence,block_id,body,payload_bytes FROM blocks ORDER BY sequence DESC LIMIT 1", transaction);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            var archived = ReadArchiveState(transaction);
            if (checkpoint.SequenceNumber != archived.Sequence || checkpoint.BlockHash != archived.BlockHash)
                throw new InvalidDataException("The persisted ledger tip is missing.");
            return;
        }
        var block = ReadVerifiedBlock(reader);
        if (block.Content.SequenceNumber != checkpoint.SequenceNumber || block.BlockHash != checkpoint.BlockHash)
            throw new InvalidDataException("The persisted ledger tip has changed.");
    }

    private SignedTelemetryBlock ReadVerifiedBlock(SqliteDataReader reader)
    {
        var block = Decode<SignedTelemetryBlock>(ReadBoundedBlob(reader, 2, _options.MaximumPayloadBytes * 2L + 131072));
        if (!LedgerProtocol.VerifyBlock(block, _blockVerifier))
            throw new InvalidDataException("A block hash or signature failed verification.");
        var content = block.Content;
        if (content.NodeId != _options.NodeId || content.LedgerId != _ledgerId
            || content.SequenceNumber != reader.GetInt64(0) || content.BlockId.ToString("D") != reader.GetString(1)
            || content.Payload.Length != reader.GetInt64(3) || content.Payload.Length > _options.MaximumPayloadBytes
            || content.EventCount > _options.MaximumEventsPerBlock)
            throw new InvalidDataException("The block's signed identity or size does not match its database row.");
        BlockPayloadValidation.Validate(block, _options.AdditionalPayloadCodecs);
        return block;
    }

    private static void MatchReceipt(SettlementReceipt receipt, SignedTelemetryBlock block)
    {
        var proof = receipt.Content;
        var content = block.Content;
        if (proof.NodeId != content.NodeId || proof.LedgerId != content.LedgerId || proof.BlockId != content.BlockId
            || proof.SequenceNumber != content.SequenceNumber || proof.BlockHash != block.BlockHash)
            throw new InvalidDataException("The receipt does not attest to this exact node, ledger, and block hash.");
    }

    private static byte[] ReadBoundedBlob(SqliteDataReader reader, int ordinal, long maximumBytes)
    {
        long size = reader.GetBytes(ordinal, 0, null, 0, 0);
        if (size < 1 || size > maximumBytes) throw new InvalidDataException("An oversized or empty database record was rejected.");
        return reader.GetFieldValue<byte[]>(ordinal);
    }

    private static T Decode<T>(byte[] bytes)
    {
        try { return JsonSerializer.Deserialize<T>(bytes) ?? throw new InvalidDataException("A database record is null."); }
        catch (JsonException error) { throw new InvalidDataException("A database record is malformed.", error); }
    }

    private SqliteCommand Command(string sql, SqliteTransaction transaction, params (string Name, object Value)[] parameters)
    {
        var command = transaction.Connection!.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value);
        return command;
    }

    private static void Initialize(SqliteConnection connection, string nodeId)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE ledger (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL,
                node_id TEXT NOT NULL, ledger_id TEXT NOT NULL,
                last_sequence INTEGER NOT NULL CHECK(last_sequence>=0), tail_hash TEXT NOT NULL);
            CREATE TABLE blocks (
                sequence INTEGER PRIMARY KEY CHECK(sequence>0), block_id TEXT NOT NULL UNIQUE,
                body BLOB NOT NULL, payload_bytes INTEGER NOT NULL CHECK(payload_bytes>0), receipt BLOB);
            INSERT INTO ledger VALUES(1,$version,$node,$ledger,0,$hash);
            """;
        command.Parameters.AddWithValue("$version", LedgerProtocol.Version);
        command.Parameters.AddWithValue("$node", nodeId);
        command.Parameters.AddWithValue("$ledger", Guid.NewGuid().ToString("D"));
        command.Parameters.AddWithValue("$hash", LedgerProtocol.GenesisHash);
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private static void EnsureMetadataIndexes(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE INDEX IF NOT EXISTS blocks_payload_size ON blocks(payload_bytes);
            CREATE INDEX IF NOT EXISTS blocks_pending ON blocks(sequence,payload_bytes) WHERE receipt IS NULL;
            """;
        command.ExecuteNonQuery();
        transaction.Commit();
    }
}
