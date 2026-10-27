using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Ingestion.Sqlite;

/// <summary>Single-writer central ledger. Receipts are published only after block, proof and tip commit together.</summary>
public sealed class SqliteIngestionStore : IIngestionStore
{
    internal const string StoredBytesSql = "SELECT COALESCE(SUM(payload_bytes),0) FROM ingested_blocks";
    private readonly SqliteConnection _connection;
    private readonly FileStream _writerLock;
    private readonly SqliteIngestionOptions _options;
    private readonly INodeTrustStore _trust;
    private readonly ISignatureVerifier _receiptVerifier;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<(string Node, Guid Ledger), LedgerCheckpoint> _tips = new();
    private bool _initialized, _disposed;
    private SqliteIngestionStore(SqliteConnection connection, FileStream writerLock, SqliteIngestionOptions options,
        INodeTrustStore trust, ISignatureVerifier receiptVerifier)
    { _connection = connection; _writerLock = writerLock; _options = options; _trust = trust; _receiptVerifier = receiptVerifier; }

    public static async Task<SqliteIngestionStore> OpenAsync(SqliteIngestionOptions options, INodeTrustStore trust,
        ISignatureVerifier receiptVerifier, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(receiptVerifier);
        options.Validate();
        cancellationToken.ThrowIfCancellationRequested();
        options = options with { DatabasePath = Path.GetFullPath(options.DatabasePath) };
        Directory.CreateDirectory(Path.GetDirectoryName(options.DatabasePath)!);
        var writerLock = new FileStream(options.DatabasePath + ".writer.lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        SqliteConnection? connection = null;
        SqliteIngestionStore? store = null;
        try
        {
            bool exists = File.Exists(options.DatabasePath);
            connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = options.DatabasePath, Mode = exists ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString());
            connection.Open();
            using (var setup = connection.CreateCommand())
            {
                setup.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;";
                setup.ExecuteNonQuery();
            }
            if (!exists) Initialize(connection);
            store = new(connection, writerLock, options, trust, receiptVerifier);
            await store.VerifyIntegrityAsync(cancellationToken).ConfigureAwait(false);
            using (var index = connection.CreateCommand())
            {
                index.CommandText = "CREATE INDEX IF NOT EXISTS ingested_blocks_payload_size ON ingested_blocks(payload_bytes)";
                index.ExecuteNonQuery();
            }
            return store;
        }
        catch
        {
            if (store is not null) await store.DisposeAsync().ConfigureAwait(false);
            else { connection?.Dispose(); writerLock.Dispose(); }
            throw;
        }
    }

    public async Task<SettlementReceipt> CommitAsync(SignedTelemetryBlock verifiedBlock, Func<SettlementReceipt> receiptFactory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(receiptFactory);
        // Keep direct store use safe as well as calls through the domain service.
        var block = IngestionValidation.VerifyAndCopy(verifiedBlock, _trust, _options.BlockLimits);
        var c = block.Content;
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction();
            var tip = ReadTip(c.NodeId, c.LedgerId, tx);
            if (tip is not null) VerifyTipEvidence(tip, tx);
            using (var select = Command($"SELECT {Columns} FROM ingested_blocks WHERE node_id=$node AND ledger_id=$ledger AND sequence=$seq", tx,
                ("$node", c.NodeId), ("$ledger", c.LedgerId.ToString("D")), ("$seq", c.SequenceNumber)))
            using (var reader = select.ExecuteReader())
            {
                if (reader.Read())
                {
                    var existing = ReadStored(reader);
                    if (existing.Block.BlockHash != block.BlockHash || existing.Block.Content.BlockId != c.BlockId)
                        throw new TelemetryRejectedException(IngestionFailure.SequenceConflict, "This sequence already identifies a different block.");
                    return existing.Receipt;
                }
            }
            long lastSequence = tip?.SequenceNumber ?? 0;
            if (lastSequence == long.MaxValue || c.SequenceNumber != lastSequence + 1)
                throw new TelemetryRejectedException(IngestionFailure.SequenceConflict, "Blocks must arrive in contiguous sequence order.");
            if (c.PreviousBlockHash != (tip?.BlockHash ?? LedgerProtocol.GenesisHash))
                throw new TelemetryRejectedException(IngestionFailure.ChainConflict, "The predecessor does not match the receiver's chain tip.");
            using (var duplicate = Command("SELECT COUNT(*) FROM ingested_blocks WHERE node_id=$node AND ledger_id=$ledger AND block_id=$id", tx,
                ("$node", c.NodeId), ("$ledger", c.LedgerId.ToString("D")), ("$id", c.BlockId.ToString("D"))))
                if (Convert.ToInt64(duplicate.ExecuteScalar()) != 0)
                    throw new TelemetryRejectedException(IngestionFailure.SequenceConflict, "A block ID cannot be reused at a different sequence.");
            using (var size = Command(StoredBytesSql, tx))
                if (Convert.ToInt64(size.ExecuteScalar()) > _options.MaximumStoredPayloadBytes - c.Payload.Length)
                    throw new TelemetryRejectedException(IngestionFailure.CapacityExceeded, "The ingestion store has reached its configured capacity.");
            var receipt = receiptFactory();
            IngestionValidation.VerifyReceipt(receipt, block, _receiptVerifier);
            byte[] receiptBytes = TelemetryJson.Encode(receipt);
            if (receiptBytes.Length > TelemetryJson.MaximumReceiptBytes) throw new InvalidDataException("The prepared receipt exceeds its wire limit.");
            using (var upsert = Command("""
                INSERT INTO ledgers(node_id,ledger_id,last_sequence,tail_hash) VALUES($node,$ledger,$seq,$hash)
                ON CONFLICT(node_id,ledger_id) DO UPDATE SET last_sequence=excluded.last_sequence,tail_hash=excluded.tail_hash
                """, tx, ("$node", c.NodeId), ("$ledger", c.LedgerId.ToString("D")), ("$seq", c.SequenceNumber), ("$hash", block.BlockHash)))
                upsert.ExecuteNonQuery();
            using (var insert = Command("""
                INSERT INTO ingested_blocks(node_id,ledger_id,sequence,block_id,block_hash,body,receipt,payload_bytes)
                VALUES($node,$ledger,$seq,$id,$hash,$body,$receipt,$size)
                """, tx, ("$node", c.NodeId), ("$ledger", c.LedgerId.ToString("D")), ("$seq", c.SequenceNumber),
                ("$id", c.BlockId.ToString("D")), ("$hash", block.BlockHash), ("$body", TelemetryJson.Encode(block)),
                ("$receipt", receiptBytes), ("$size", c.Payload.Length)))
                insert.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested();
            tx.Commit();
            _tips[(c.NodeId, c.LedgerId)] = new(c.NodeId, c.LedgerId, c.SequenceNumber, block.BlockHash);
            return receipt; // No receipt escapes before COMMIT succeeds.
        }
        finally { _gate.Release(); }
    }

    public async Task<IngestedBlock?> ReadAsync(string nodeId, Guid ledgerId, long sequenceNumber, CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(deferred: true);
            _ = ReadTip(nodeId, ledgerId, tx);
            using var command = Command($"SELECT {Columns} FROM ingested_blocks WHERE node_id=$node AND ledger_id=$ledger AND sequence=$seq", tx,
                ("$node", nodeId), ("$ledger", ledgerId.ToString("D")), ("$seq", sequenceNumber));
            using var reader = command.ExecuteReader();
            return reader.Read() ? ReadStored(reader) : null;
        }
        finally { _gate.Release(); }
    }
    public async Task<LedgerCheckpoint?> GetCheckpointAsync(string nodeId, Guid ledgerId, CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try { using var tx = _connection.BeginTransaction(deferred: true); return ReadTip(nodeId, ledgerId, tx); }
        finally { _gate.Release(); }
    }
    public async Task VerifyIntegrityAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(deferred: true);
            using (var check = Command("PRAGMA quick_check", tx))
                if (check.ExecuteScalar() as string != "ok") throw new InvalidDataException("SQLite integrity verification failed.");
            using (var version = Command("SELECT version FROM store_metadata WHERE singleton=1", tx))
                if (Convert.ToInt32(version.ExecuteScalar()) != 1) throw new InvalidDataException("Unsupported ingestion schema.");
            var actual = new Dictionary<(string Node, Guid Ledger), LedgerCheckpoint>();
            using (var select = Command($"SELECT {Columns} FROM ingested_blocks ORDER BY node_id,ledger_id,sequence", tx))
            using (var reader = select.ExecuteReader())
            {
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var item = ReadStored(reader);
                    var c = item.Block.Content;
                    actual.TryGetValue((c.NodeId, c.LedgerId), out var previous);
                    if (c.SequenceNumber != (previous?.SequenceNumber ?? 0) + 1
                        || c.PreviousBlockHash != (previous?.BlockHash ?? LedgerProtocol.GenesisHash))
                        throw new InvalidDataException("The ingestion store has a sequence gap or broken chain.");
                    actual[(c.NodeId, c.LedgerId)] = new(c.NodeId, c.LedgerId, c.SequenceNumber, item.Block.BlockHash);
                }
            }
            var persisted = new Dictionary<(string Node, Guid Ledger), LedgerCheckpoint>();
            using (var select = Command("SELECT node_id,ledger_id,last_sequence,tail_hash FROM ledgers", tx))
            using (var reader = select.ExecuteReader())
                while (reader.Read())
                {
                    var tip = new LedgerCheckpoint(reader.GetString(0), Guid.ParseExact(reader.GetString(1), "D"), reader.GetInt64(2), reader.GetString(3));
                    persisted.Add((tip.NodeId, tip.LedgerId), tip);
                }
            if (!SameTips(actual, persisted) || (_initialized && !SameTips(actual, _tips)))
                throw new InvalidDataException("The ingestion chain tips do not match retained evidence or the active writer.");
            _tips.Clear();
            foreach (var pair in actual) _tips.Add(pair.Key, pair.Value);
            _initialized = true;
        }
        finally { _gate.Release(); }
    }
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { if (_disposed) return; _disposed = true; try { _connection.Dispose(); } finally { _writerLock.Dispose(); } }
        finally { _gate.Release(); }
    }
    private async Task EnterAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (_disposed) { _gate.Release(); throw new ObjectDisposedException(nameof(SqliteIngestionStore)); }
    }
    private LedgerCheckpoint? ReadTip(string nodeId, Guid ledgerId, SqliteTransaction tx)
    {
        using var select = Command("SELECT last_sequence,tail_hash FROM ledgers WHERE node_id=$node AND ledger_id=$ledger", tx,
            ("$node", nodeId), ("$ledger", ledgerId.ToString("D")));
        using var reader = select.ExecuteReader();
        var tip = reader.Read() ? new LedgerCheckpoint(nodeId, ledgerId, reader.GetInt64(0), reader.GetString(1)) : null;
        _tips.TryGetValue((nodeId, ledgerId), out var known);
        if (_initialized && tip != known) throw new InvalidDataException("The ingestion chain tip changed outside this writer.");
        return tip;
    }
    private IngestedBlock ReadStored(SqliteDataReader reader)
    {
        var block = TelemetryJson.Decode<SignedTelemetryBlock>(Blob(reader, 5, TelemetryJson.MaximumBlockBytes), TelemetryJson.MaximumBlockBytes);
        try { block = IngestionValidation.VerifyAndCopy(block, _trust, _options.BlockLimits); }
        catch (TelemetryRejectedException error) { throw new InvalidDataException("Stored telemetry failed verification.", error); }
        var c = block.Content;
        if (c.NodeId != reader.GetString(0) || c.LedgerId.ToString("D") != reader.GetString(1) || c.SequenceNumber != reader.GetInt64(2)
            || c.BlockId.ToString("D") != reader.GetString(3) || block.BlockHash != reader.GetString(4) || c.Payload.Length != reader.GetInt64(7))
            throw new InvalidDataException("Stored block identity or size does not match its signed content.");
        var receipt = TelemetryJson.Decode<SettlementReceipt>(Blob(reader, 6, TelemetryJson.MaximumReceiptBytes), TelemetryJson.MaximumReceiptBytes);
        IngestionValidation.VerifyReceipt(receipt, block, _receiptVerifier);
        return new(block, receipt);
    }
    private void VerifyTipEvidence(LedgerCheckpoint tip, SqliteTransaction tx)
    {
        using var command = Command($"SELECT {Columns} FROM ingested_blocks WHERE node_id=$node AND ledger_id=$ledger AND sequence=$seq", tx,
            ("$node", tip.NodeId), ("$ledger", tip.LedgerId.ToString("D")), ("$seq", tip.SequenceNumber));
        using var reader = command.ExecuteReader();
        if (!reader.Read() || ReadStored(reader).Block.BlockHash != tip.BlockHash)
            throw new InvalidDataException("The receiver's retained chain tip is missing or invalid.");
    }
    private static byte[] Blob(SqliteDataReader reader, int ordinal, int maximum)
    {
        long length = reader.GetBytes(ordinal, 0, null, 0, 0);
        if (length < 1 || length > maximum) throw new InvalidDataException("Stored record exceeds its size limit.");
        return reader.GetFieldValue<byte[]>(ordinal);
    }
    private static bool SameTips(Dictionary<(string, Guid), LedgerCheckpoint> a, Dictionary<(string, Guid), LedgerCheckpoint> b) =>
        a.Count == b.Count && a.All(pair => b.TryGetValue(pair.Key, out var value) && value == pair.Value);
    private SqliteCommand Command(string sql, SqliteTransaction tx, params (string Name, object Value)[] parameters)
    {
        var command = _connection.CreateCommand(); command.Transaction = tx; command.CommandText = sql;
        foreach (var item in parameters) command.Parameters.AddWithValue(item.Name, item.Value);
        return command;
    }
    private const string Columns = "node_id,ledger_id,sequence,block_id,block_hash,body,receipt,payload_bytes";
    private static void Initialize(SqliteConnection connection)
    {
        using var tx = connection.BeginTransaction();
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = """
            CREATE TABLE store_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);
            INSERT INTO store_metadata VALUES(1,1);
            CREATE TABLE ledgers(node_id TEXT NOT NULL,ledger_id TEXT NOT NULL,last_sequence INTEGER NOT NULL CHECK(last_sequence>0),
                tail_hash TEXT NOT NULL,PRIMARY KEY(node_id,ledger_id));
            CREATE TABLE ingested_blocks(node_id TEXT NOT NULL,ledger_id TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),
                block_id TEXT NOT NULL,block_hash TEXT NOT NULL,body BLOB NOT NULL,receipt BLOB NOT NULL,
                payload_bytes INTEGER NOT NULL CHECK(payload_bytes>0),PRIMARY KEY(node_id,ledger_id,sequence),
                UNIQUE(node_id,ledger_id,block_id),FOREIGN KEY(node_id,ledger_id) REFERENCES ledgers(node_id,ledger_id));
            """;
        command.ExecuteNonQuery(); tx.Commit();
    }
}
