using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Ingestion;

namespace Mrbr.Bastion.Auditing.Sqlite;

/// <summary>Durable nonce lifecycle and signed assessment history, with atomic single-use consumption.</summary>
public sealed class SqliteHeartbeatAuditStore : IHeartbeatAuditStore, IAuditHistoryReader
{
    private readonly SqliteConnection _connection;
    private readonly FileStream _writerLock;
    private readonly SqliteAuditOptions _options;
    private readonly INodeTrustStore _trust;
    private readonly ISignatureVerifier _serverVerifier;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<(string, Guid), Head> _heads = new();
    private bool _initialized, _disposed;
    private sealed record Head(long Sequence, string Hash, Guid ChallengeId, DateTimeOffset AcceptedUtc);
    private sealed record Entry(SignedAuditRequest Request, SignedAuditChallenge Challenge, SignedAuditResponse? Response, SignedAuditResult? Result)
    {
        public AuditRecord Complete => new(Request, Challenge, Response ?? throw new InvalidDataException("Missing audit response."),
            Result ?? throw new InvalidDataException("Missing audit assessment."));
    }
    private SqliteHeartbeatAuditStore(SqliteConnection connection, FileStream writerLock, SqliteAuditOptions options,
        INodeTrustStore trust, ISignatureVerifier verifier, TimeProvider time)
    { _connection = connection; _writerLock = writerLock; _options = options; _trust = trust; _serverVerifier = verifier; _time = time; }

    public static async Task<SqliteHeartbeatAuditStore> OpenAsync(SqliteAuditOptions options, INodeTrustStore trust,
        ISignatureVerifier serverVerifier, TimeProvider? timeProvider = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options); options.Validate();
        ArgumentNullException.ThrowIfNull(trust); ArgumentNullException.ThrowIfNull(serverVerifier);
        cancellationToken.ThrowIfCancellationRequested();
        options = options with { DatabasePath = Path.GetFullPath(options.DatabasePath) };
        Directory.CreateDirectory(Path.GetDirectoryName(options.DatabasePath)!);
        var writerLock = new FileStream(options.DatabasePath + ".writer.lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        SqliteConnection? connection = null; SqliteHeartbeatAuditStore? store = null;
        try
        {
            bool exists = File.Exists(options.DatabasePath);
            connection = new(new SqliteConnectionStringBuilder { DataSource = options.DatabasePath, Mode = exists ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString());
            connection.Open();
            using (var setup = connection.CreateCommand())
            {
                setup.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;";
                setup.ExecuteNonQuery();
            }
            if (!exists) Initialize(connection);
            store = new(connection, writerLock, options, trust, serverVerifier, timeProvider ?? TimeProvider.System);
            await store.VerifyIntegrityAsync(cancellationToken).ConfigureAwait(false);
            return store;
        }
        catch
        {
            if (store is not null) await store.DisposeAsync().ConfigureAwait(false);
            else { connection?.Dispose(); writerLock.Dispose(); }
            throw;
        }
    }
    public async Task<SignedAuditChallenge> GetOrCreateAsync(SignedAuditRequest request,
        Func<DateTimeOffset, SignedAuditChallenge> factory, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(factory);
        request = AuditAuthentication.Verify(request, _trust);
        var r = request.Content;
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction();
            var previous = ReadLatest(r.NodeId, r.LedgerId, tx);
            var existing = SelectEntry("node_id=$node AND ledger_id=$ledger AND request_id=$request", tx,
                ("$node", r.NodeId), ("$ledger", r.LedgerId.ToString("D")), ("$request", r.RequestId.ToString("D")));
            if (existing is not null)
            {
                if (AuditProtocol.Hash(AuditProtocol.Encode(r)) != AuditProtocol.Hash(AuditProtocol.Encode(existing.Request.Content)))
                    Reject(AuditFailure.ResponseConflict, "This request ID already identifies different signed content.");
                return existing.Challenge;
            }
            var now = _time.GetUtcNow();
            if (previous is not null && now < previous.Result.Content.AcceptedUtc)
                throw new InvalidDataException("The receiver clock moved behind its last accepted audit.");
            using (var active = Command("SELECT COUNT(*) FROM audit_entries WHERE node_id=$node AND ledger_id=$ledger AND result_json IS NULL AND expires_ticks>$now", tx,
                ("$node", r.NodeId), ("$ledger", r.LedgerId.ToString("D")), ("$now", now.UtcTicks)))
                if (Convert.ToInt64(active.ExecuteScalar()) != 0) Reject(AuditFailure.ChallengeOutstanding, "An outstanding challenge must finish or expire first.");
            using (var count = Command("SELECT COUNT(*) FROM audit_entries", tx))
                if (Convert.ToInt64(count.ExecuteScalar()) >= _options.MaximumStoredAudits) Reject(AuditFailure.CapacityExceeded, "The audit history capacity was reached.");
            var challenge = factory(now);
            if (!AuditProtocol.Verify(challenge, _serverVerifier)) throw new InvalidDataException("The prepared challenge failed signature verification.");
            AuditProtocol.Bind(challenge, request);
            if (challenge.Content.IssuedUtc != now) throw new InvalidDataException("A challenge must use the receiver's issuance time.");
            byte[] requestBytes = Encode(request), challengeBytes = Encode(challenge);
            // Reserve space for both response and result so another request cannot consume an active nonce's commit budget.
            long reserved;
            using (var active = Command("SELECT COUNT(*) FROM audit_entries WHERE result_json IS NULL AND expires_ticks>$now", tx, ("$now", now.UtcTicks)))
                reserved = Convert.ToInt64(active.ExecuteScalar()) * (2L * AuditProtocol.MaximumEnvelopeBytes);
            EnsureCapacity(tx, reserved + requestBytes.Length + challengeBytes.Length + 2L * AuditProtocol.MaximumEnvelopeBytes);
            var c = challenge.Content;
            using (var insert = Command("""
                INSERT INTO audit_entries(node_id,ledger_id,request_id,challenge_id,request_hash,challenge_hash,request_json,challenge_json,issued_ticks,expires_ticks)
                VALUES($node,$ledger,$request,$challenge,$requestHash,$challengeHash,$requestJson,$challengeJson,$issued,$expires)
                """, tx, ("$node", r.NodeId), ("$ledger", r.LedgerId.ToString("D")), ("$request", r.RequestId.ToString("D")),
                ("$challenge", c.ChallengeId.ToString("D")), ("$requestHash", c.RequestHash), ("$challengeHash", AuditProtocol.Hash(AuditProtocol.Encode(c))),
                ("$requestJson", requestBytes), ("$challengeJson", challengeBytes), ("$issued", c.IssuedUtc.UtcTicks), ("$expires", c.ExpiresUtc.UtcTicks))) insert.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
            return challenge;
        }
        finally { _gate.Release(); }
    }
    public async Task<SignedAuditResult> CompleteAsync(SignedAuditResponse response,
        Func<AuditRecord?, SignedAuditChallenge, DateTimeOffset, SignedAuditResult> evaluate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evaluate);
        response = AuditAuthentication.Verify(response, _trust);
        var r = response.Content;
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction();
            var previous = ReadLatest(r.NodeId, r.LedgerId, tx);
            var entry = SelectEntry("challenge_id=$id", tx, ("$id", r.ChallengeId.ToString("D")));
            if (entry is null) Reject(AuditFailure.ChallengeMismatch, "Unknown audit challenge.");
            try { AuditProtocol.Bind(response, entry.Challenge); }
            catch (InvalidDataException) { Reject(AuditFailure.ChallengeMismatch, "The response does not match its issued challenge."); }
            string responseHash = AuditProtocol.Hash(AuditProtocol.Encode(r));
            if (entry.Result is not null)
            {
                if (entry.Result.Content.ResponseHash != responseHash) Reject(AuditFailure.ResponseConflict, "This challenge was consumed by different signed content.");
                return entry.Result; // Retries never update AcceptedUtc, head, counters, or node liveness.
            }
            var now = _time.GetUtcNow();
            if (previous is not null && now < previous.Result.Content.AcceptedUtc)
                throw new InvalidDataException("The receiver clock moved behind its last accepted audit.");
            if (now < entry.Challenge.Content.IssuedUtc || now >= entry.Challenge.Content.ExpiresUtc)
                Reject(AuditFailure.ChallengeExpired, "The challenge is outside its validity window.");
            var result = evaluate(previous, entry.Challenge, now);
            if (!AuditProtocol.Verify(result, _serverVerifier)) throw new InvalidDataException("The prepared assessment failed signature verification.");
            AuditProtocol.Bind(result, response);
            var a = result.Content;
            string priorHash = previous is null ? AuditProtocol.GenesisHash : AuditProtocol.Hash(AuditProtocol.Encode(previous.Result.Content));
            if (a.AuditSequenceNumber != checked((previous?.Result.Content.AuditSequenceNumber ?? 0) + 1)
                || a.PreviousResultHash != priorHash || a.AcceptedUtc != now) throw new InvalidDataException("Invalid audit assessment lineage or time.");
            byte[] responseBytes = Encode(response), resultBytes = Encode(result);
            EnsureCapacity(tx, responseBytes.Length + resultBytes.Length);
            string resultHash = AuditProtocol.Hash(AuditProtocol.Encode(a));
            using (var update = Command("""
                UPDATE audit_entries SET response_json=$response,response_hash=$responseHash,result_json=$result,result_hash=$hash,
                    accepted_sequence=$seq,accepted_ticks=$accepted WHERE challenge_id=$id AND result_json IS NULL
                """, tx, ("$response", responseBytes), ("$responseHash", responseHash), ("$result", resultBytes), ("$hash", resultHash),
                ("$seq", a.AuditSequenceNumber), ("$accepted", now.UtcTicks), ("$id", a.ChallengeId.ToString("D"))))
                if (update.ExecuteNonQuery() != 1) throw new InvalidDataException("The challenge consumption state changed.");
            using (var head = Command("""
                INSERT INTO node_heads(node_id,ledger_id,sequence,result_hash,challenge_id,accepted_ticks) VALUES($node,$ledger,$seq,$hash,$id,$time)
                ON CONFLICT(node_id,ledger_id) DO UPDATE SET sequence=excluded.sequence,result_hash=excluded.result_hash,challenge_id=excluded.challenge_id,accepted_ticks=excluded.accepted_ticks
                """, tx, ("$node", r.NodeId), ("$ledger", r.LedgerId.ToString("D")), ("$seq", a.AuditSequenceNumber),
                ("$hash", resultHash), ("$id", a.ChallengeId.ToString("D")), ("$time", now.UtcTicks))) head.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
            _heads[(r.NodeId, r.LedgerId)] = new(a.AuditSequenceNumber, resultHash, a.ChallengeId, now);
            return result;
        }
        finally { _gate.Release(); }
    }
    public async Task<AuditRecord?> ReadLatestAsync(string nodeId, Guid ledgerId, CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try { using var tx = _connection.BeginTransaction(deferred: true); return ReadLatest(nodeId, ledgerId, tx); }
        finally { _gate.Release(); }
    }
    public async Task<SignedAuditChallenge?> ReadChallengeAsync(Guid challengeId, CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(deferred: true);
            return SelectEntry("challenge_id=$id", tx, ("$id", challengeId.ToString("D")))?.Challenge;
        }
        finally { _gate.Release(); }
    }
    public async Task<AuditHistoryPage> ReadHistoryAsync(string nodeId, Guid ledgerId, long? beforeSequence = null,
        int limit = 25, CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 100 || beforeSequence is < 1) throw new ArgumentOutOfRangeException(nameof(limit));
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(deferred: true);
            var latest = ReadLatest(nodeId, ledgerId, tx);
            if (latest is null || beforeSequence == 1) return new([], null);
            long expected = latest.Result.Content.AuditSequenceNumber;
            string expectedHash = AuditProtocol.Hash(AuditProtocol.Encode(latest.Result.Content));
            if (beforeSequence is { } before && before <= expected)
            {
                var boundary = SelectEntry("node_id=$node AND ledger_id=$ledger AND accepted_sequence=$seq", tx,
                    ("$node", nodeId), ("$ledger", ledgerId.ToString("D")), ("$seq", before))
                    ?? throw new InvalidDataException("The audit history boundary is missing.");
                expected = before - 1; expectedHash = boundary.Complete.Result.Content.PreviousResultHash;
            }
            long expectedCount = Math.Min(limit, expected);
            var records = new List<AuditRecord>();
            using var command = Command($"SELECT {Columns} FROM audit_entries WHERE node_id=$node AND ledger_id=$ledger AND accepted_sequence<=$seq ORDER BY accepted_sequence DESC LIMIT $limit", tx,
                ("$node", nodeId), ("$ledger", ledgerId.ToString("D")), ("$seq", expected), ("$limit", limit));
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var record = ReadEntry(reader).Complete; var result = record.Result.Content;
                if (result.AuditSequenceNumber != expected || AuditProtocol.Hash(AuditProtocol.Encode(result)) != expectedHash)
                    throw new InvalidDataException("The audit history has a gap or a broken hash chain.");
                records.Add(record); expected--; expectedHash = result.PreviousResultHash;
            }
            if (records.Count != expectedCount || (expected == 0 && expectedHash != AuditProtocol.GenesisHash))
                throw new InvalidDataException("The audit history is incomplete.");
            return new(records.ToArray(), expected > 0 ? records[^1].Result.Content.AuditSequenceNumber : null);
        }
        finally { _gate.Release(); }
    }
    public async Task VerifyIntegrityAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(deferred: true);
            using (var check = Command("PRAGMA quick_check", tx))
                if (check.ExecuteScalar() as string != "ok") throw new InvalidDataException("SQLite audit integrity check failed.");
            using (var version = Command("SELECT version FROM audit_metadata WHERE singleton=1", tx))
                if (Convert.ToInt32(version.ExecuteScalar()) != 1) throw new InvalidDataException("Unsupported audit schema.");
            var actual = new Dictionary<(string, Guid), Head>();
            using (var command = Command($"SELECT {Columns} FROM audit_entries ORDER BY node_id,ledger_id,accepted_sequence", tx))
            using (var reader = command.ExecuteReader())
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var entry = ReadEntry(reader);
                    if (entry.Result is not { } result) continue;
                    var a = result.Content; actual.TryGetValue((a.NodeId, a.LedgerId), out var previous);
                    if (a.AuditSequenceNumber != (previous?.Sequence ?? 0) + 1 || a.PreviousResultHash != (previous?.Hash ?? AuditProtocol.GenesisHash)
                        || (previous is not null && a.AcceptedUtc < previous.AcceptedUtc))
                        throw new InvalidDataException("The assessment history has a gap or broken hash chain.");
                    actual[(a.NodeId, a.LedgerId)] = new(a.AuditSequenceNumber, AuditProtocol.Hash(AuditProtocol.Encode(a)), a.ChallengeId, a.AcceptedUtc);
                }
            var persisted = new Dictionary<(string, Guid), Head>();
            using (var command = Command("SELECT node_id,ledger_id,sequence,result_hash,challenge_id,accepted_ticks FROM node_heads", tx))
            using (var reader = command.ExecuteReader())
                while (reader.Read()) persisted.Add((reader.GetString(0), Guid.ParseExact(reader.GetString(1), "D")),
                    new(reader.GetInt64(2), reader.GetString(3), Guid.ParseExact(reader.GetString(4), "D"), new DateTimeOffset(reader.GetInt64(5), TimeSpan.Zero)));
            if (!Same(actual, persisted) || (_initialized && !Same(actual, _heads))) throw new InvalidDataException("The stored audit heads do not match verified history.");
            _heads.Clear(); foreach (var item in actual) _heads.Add(item.Key, item.Value); _initialized = true;
        }
        finally { _gate.Release(); }
    }
    private AuditRecord? ReadLatest(string nodeId, Guid ledgerId, SqliteTransaction tx)
    {
        Head? persisted = null;
        using (var command = Command("SELECT sequence,result_hash,challenge_id,accepted_ticks FROM node_heads WHERE node_id=$node AND ledger_id=$ledger", tx,
            ("$node", nodeId), ("$ledger", ledgerId.ToString("D"))))
        using (var reader = command.ExecuteReader())
            if (reader.Read()) persisted = new(reader.GetInt64(0), reader.GetString(1), Guid.ParseExact(reader.GetString(2), "D"), new DateTimeOffset(reader.GetInt64(3), TimeSpan.Zero));
        _heads.TryGetValue((nodeId, ledgerId), out var known);
        if (_initialized && persisted != known) throw new InvalidDataException("The active audit head changed outside this writer.");
        if (persisted is null) return null;
        var entry = SelectEntry("challenge_id=$id", tx, ("$id", persisted.ChallengeId.ToString("D")));
        if (entry?.Result is not { } result || result.Content.NodeId != nodeId || result.Content.LedgerId != ledgerId
            || result.Content.AuditSequenceNumber != persisted.Sequence || result.Content.AcceptedUtc != persisted.AcceptedUtc
            || AuditProtocol.Hash(AuditProtocol.Encode(result.Content)) != persisted.Hash) throw new InvalidDataException("The active assessment evidence is missing or invalid.");
        return entry.Complete;
    }
    private Entry? SelectEntry(string where, SqliteTransaction tx, params (string, object)[] parameters)
    {
        using var command = Command($"SELECT {Columns} FROM audit_entries WHERE {where}", tx, parameters);
        using var reader = command.ExecuteReader(); return reader.Read() ? ReadEntry(reader) : null;
    }
    private Entry ReadEntry(SqliteDataReader reader)
    {
        SignedAuditRequest request; SignedAuditResponse? response = null;
        try
        {
            request = AuditAuthentication.Verify(Decode<SignedAuditRequest>(reader, 6), _trust);
            if (!reader.IsDBNull(10)) response = AuditAuthentication.Verify(Decode<SignedAuditResponse>(reader, 10), _trust);
        }
        catch (AuditRejectedException error) { throw new InvalidDataException("Stored node audit signatures failed verification.", error); }
        var challenge = Decode<SignedAuditChallenge>(reader, 7);
        if (!AuditProtocol.Verify(challenge, _serverVerifier)) throw new InvalidDataException("Stored challenge signature failed verification.");
        AuditProtocol.Bind(challenge, request);
        var r = request.Content; var c = challenge.Content;
        if (r.NodeId != reader.GetString(0) || r.LedgerId.ToString("D") != reader.GetString(1) || r.RequestId.ToString("D") != reader.GetString(2)
            || c.ChallengeId.ToString("D") != reader.GetString(3) || c.RequestHash != reader.GetString(4)
            || AuditProtocol.Hash(AuditProtocol.Encode(c)) != reader.GetString(5) || c.IssuedUtc.UtcTicks != reader.GetInt64(8) || c.ExpiresUtc.UtcTicks != reader.GetInt64(9))
            throw new InvalidDataException("Stored challenge identity or time differs from signed evidence.");
        if (reader.IsDBNull(12))
        {
            if (response is not null || !reader.IsDBNull(11) || !reader.IsDBNull(13) || !reader.IsDBNull(14) || !reader.IsDBNull(15))
                throw new InvalidDataException("Incomplete challenge consumption state.");
            return new(request, challenge, null, null);
        }
        if (response is null) throw new InvalidDataException("An assessment has no signed response.");
        var result = Decode<SignedAuditResult>(reader, 12);
        if (!AuditProtocol.Verify(result, _serverVerifier)) throw new InvalidDataException("Stored assessment signature failed verification.");
        AuditProtocol.Bind(response, challenge); AuditProtocol.Bind(result, response);
        var a = result.Content;
        if (a.ResponseHash != reader.GetString(11) || AuditProtocol.Hash(AuditProtocol.Encode(a)) != reader.GetString(13)
            || a.AuditSequenceNumber != reader.GetInt64(14) || a.AcceptedUtc.UtcTicks != reader.GetInt64(15)
            || a.AcceptedUtc < c.IssuedUtc || a.AcceptedUtc >= c.ExpiresUtc) throw new InvalidDataException("Stored assessment time, sequence or hash differs from signed evidence.");
        return new(request, challenge, response, result);
    }
    private static byte[] Encode<T>(T value)
    {
        var bytes = TelemetryJson.Encode(value);
        if (bytes.Length > AuditProtocol.MaximumEnvelopeBytes) throw new InvalidDataException("The audit envelope exceeds its storage limit.");
        return bytes;
    }
    private static T Decode<T>(SqliteDataReader reader, int ordinal)
    {
        long length = reader.GetBytes(ordinal, 0, null, 0, 0);
        if (length < 1 || length > AuditProtocol.MaximumEnvelopeBytes) throw new InvalidDataException("An audit envelope exceeds its storage limit.");
        return TelemetryJson.Decode<T>(reader.GetFieldValue<byte[]>(ordinal), AuditProtocol.MaximumEnvelopeBytes);
    }
    private void EnsureCapacity(SqliteTransaction tx, long additional)
    {
        using var command = Command("SELECT COALESCE(SUM(length(request_json)+length(challenge_json)+COALESCE(length(response_json),0)+COALESCE(length(result_json),0)),0) FROM audit_entries", tx);
        if (Convert.ToInt64(command.ExecuteScalar()) > _options.MaximumStoredBytes - additional) Reject(AuditFailure.CapacityExceeded, "The audit envelope storage capacity was reached.");
    }
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { if (_disposed) return; _disposed = true; try { _connection.Dispose(); } finally { _writerLock.Dispose(); } }
        finally { _gate.Release(); }
    }
    private async Task EnterAsync(CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        if (_disposed) { _gate.Release(); throw new ObjectDisposedException(nameof(SqliteHeartbeatAuditStore)); }
    }
    private SqliteCommand Command(string sql, SqliteTransaction tx, params (string Name, object Value)[] values)
    {
        var command = _connection.CreateCommand(); command.Transaction = tx; command.CommandText = sql;
        foreach (var item in values) command.Parameters.AddWithValue(item.Name, item.Value); return command;
    }
    private static bool Same(Dictionary<(string, Guid), Head> a, Dictionary<(string, Guid), Head> b) => a.Count == b.Count && a.All(x => b.TryGetValue(x.Key, out var h) && h == x.Value);
    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Reject(AuditFailure failure, string message) => throw new AuditRejectedException(failure, message);
    private const string Columns = "node_id,ledger_id,request_id,challenge_id,request_hash,challenge_hash,request_json,challenge_json,issued_ticks,expires_ticks,response_json,response_hash,result_json,result_hash,accepted_sequence,accepted_ticks";
    private static void Initialize(SqliteConnection connection)
    {
        using var tx = connection.BeginTransaction(); using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = """
            CREATE TABLE audit_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);
            INSERT INTO audit_metadata VALUES(1,1);
            CREATE TABLE audit_entries(node_id TEXT NOT NULL,ledger_id TEXT NOT NULL,request_id TEXT NOT NULL,challenge_id TEXT NOT NULL PRIMARY KEY,
                request_hash TEXT NOT NULL,challenge_hash TEXT NOT NULL,request_json BLOB NOT NULL,challenge_json BLOB NOT NULL,issued_ticks INTEGER NOT NULL,expires_ticks INTEGER NOT NULL,
                response_json BLOB,response_hash TEXT,result_json BLOB,result_hash TEXT,accepted_sequence INTEGER,accepted_ticks INTEGER,
                UNIQUE(node_id,ledger_id,request_id),UNIQUE(node_id,ledger_id,accepted_sequence),
                CHECK((result_json IS NULL AND response_json IS NULL AND response_hash IS NULL AND result_hash IS NULL AND accepted_sequence IS NULL AND accepted_ticks IS NULL)
                    OR (result_json IS NOT NULL AND response_json IS NOT NULL AND response_hash IS NOT NULL AND result_hash IS NOT NULL AND accepted_sequence IS NOT NULL AND accepted_sequence>0 AND accepted_ticks IS NOT NULL)));
            CREATE INDEX active_challenges ON audit_entries(node_id,ledger_id,expires_ticks) WHERE result_json IS NULL;
            CREATE TABLE node_heads(node_id TEXT NOT NULL,ledger_id TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),result_hash TEXT NOT NULL,
                challenge_id TEXT NOT NULL,accepted_ticks INTEGER NOT NULL,PRIMARY KEY(node_id,ledger_id),FOREIGN KEY(challenge_id) REFERENCES audit_entries(challenge_id));
            """;
        command.ExecuteNonQuery(); tx.Commit();
    }
}
