using Microsoft.Data.Sqlite;

namespace Mrbr.Bastion.Alerting.Sqlite;

public sealed record SqliteAlertOptions
{
    public required string DatabasePath { get; init; }
    public int MaximumStoredAlerts { get; init; } = 100000;
}

/// <summary>Transactional condition transitions and operator acknowledgements, separate from signed audit evidence.</summary>
public sealed partial class SqliteAlertStore : IAlertStore, IAlertEventFeed
{
    private readonly SqliteConnection _connection;
    private readonly FileStream _writer;
    private readonly int _capacity;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _disposed;
    private SqliteAlertStore(SqliteConnection connection, FileStream writer, int capacity)
    { _connection = connection; _writer = writer; _capacity = capacity; }

    public static Task<SqliteAlertStore> OpenAsync(SqliteAlertOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options); ArgumentException.ThrowIfNullOrWhiteSpace(options.DatabasePath);
        if (options.MaximumStoredAlerts is < 1 or > 10000000) throw new ArgumentOutOfRangeException(nameof(options));
        cancellationToken.ThrowIfCancellationRequested();
        string path = Path.GetFullPath(options.DatabasePath); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var writer = new FileStream(path + ".writer.lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        SqliteConnection? connection = null;
        try
        {
            bool exists = File.Exists(path);
            connection = new(new SqliteConnectionStringBuilder { DataSource = path, Mode = exists ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;";
            command.ExecuteNonQuery();
            if (!exists)
            {
                using var tx = connection.BeginTransaction(); command.Transaction = tx;
                command.CommandText = """
                    CREATE TABLE alert_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);
                    INSERT INTO alert_metadata VALUES(1,1);
                    CREATE TABLE alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,node_id TEXT NOT NULL,ledger_id TEXT NOT NULL,code TEXT NOT NULL,
                        severity INTEGER NOT NULL CHECK(severity IN(0,1)),opened_ticks INTEGER NOT NULL,last_ticks INTEGER NOT NULL,
                        ack_ticks INTEGER,ack_actor TEXT,resolved_ticks INTEGER,
                        CHECK(last_ticks>=opened_ticks),CHECK((ack_ticks IS NULL AND ack_actor IS NULL) OR (ack_ticks>=opened_ticks AND ack_actor IS NOT NULL)),
                        CHECK(resolved_ticks IS NULL OR (resolved_ticks>=last_ticks AND (ack_ticks IS NULL OR resolved_ticks>=ack_ticks))));
                    CREATE UNIQUE INDEX one_active_condition ON alerts(node_id,ledger_id,code) WHERE resolved_ticks IS NULL;
                    CREATE INDEX alert_server_history ON alerts(node_id,ledger_id,id DESC);
                    CREATE TABLE alert_events(id INTEGER PRIMARY KEY AUTOINCREMENT,alert_id INTEGER NOT NULL REFERENCES alerts(id),
                        kind INTEGER NOT NULL CHECK(kind IN(0,1,2)),occurred_ticks INTEGER NOT NULL,actor TEXT);
                    CREATE INDEX alert_event_history ON alert_events(alert_id,id);
                    CREATE TABLE observation_heads(node_id TEXT NOT NULL,ledger_id TEXT NOT NULL,observed_ticks INTEGER NOT NULL,PRIMARY KEY(node_id,ledger_id));
                    """;
                command.ExecuteNonQuery(); tx.Commit(); command.Transaction = null;
            }
            command.CommandText = "PRAGMA quick_check";
            if (command.ExecuteScalar() as string != "ok") throw new InvalidDataException("Alert database integrity check failed.");
            command.CommandText = "SELECT version FROM alert_metadata WHERE singleton=1";
            int version = Convert.ToInt32(command.ExecuteScalar());
            if (version == 1) { MigrateEventFeed(connection);version=2; }
            if(version==2)
            {
                using var tx=connection.BeginTransaction();command.Transaction=tx;
                command.CommandText="""
                    ALTER TABLE alerts ADD COLUMN category INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE alerts ADD COLUMN subject TEXT NOT NULL DEFAULT '';
                    DROP INDEX one_active_condition;
                    CREATE UNIQUE INDEX one_active_condition ON alerts(node_id,ledger_id,category,code,subject) WHERE resolved_ticks IS NULL;
                    CREATE TABLE exposure_heads(node_id TEXT NOT NULL,ledger_id TEXT NOT NULL,scope TEXT NOT NULL,observed_ticks INTEGER NOT NULL,PRIMARY KEY(node_id,ledger_id,scope));
                    UPDATE alert_metadata SET version=3 WHERE singleton=1;
                    """;command.ExecuteNonQuery();tx.Commit();command.Transaction=null;
            }
            else if (version != 3) throw new InvalidDataException("Unsupported alert schema.");
            command.CommandText = "SELECT feed_id FROM alert_feed WHERE singleton=1";
            var feedId = Guid.ParseExact((string)(command.ExecuteScalar() ?? throw new InvalidDataException("Missing alert feed identity.")), "D");
            if (feedId == Guid.Empty) throw new InvalidDataException("Invalid alert feed identity.");
            command.CommandText = "PRAGMA foreign_key_check";
            using (var reader = command.ExecuteReader()) if (reader.Read()) throw new InvalidDataException("Alert history references missing records.");
            return Task.FromResult(new SqliteAlertStore(connection, writer, options.MaximumStoredAlerts) { _feedId = feedId });
        }
        catch { connection?.Dispose(); writer.Dispose(); throw; }
    }
    public async Task ApplyAsync(AlertObservation observation, CancellationToken cancellationToken = default)
    {
        HealthAlertPolicy.Validate(observation);
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(); var o = observation;
            if(o.Category==AlertCategory.Monitoring)AdvanceClock(tx,o.NodeId,o.LedgerId,o.ObservedUtc);
            else
            {
                using var check=Command("SELECT observed_ticks FROM exposure_heads WHERE node_id=$n AND ledger_id=$l AND scope=$s",tx,("$n",o.NodeId),("$l",o.LedgerId.ToString("D")),("$s",o.SubjectPrefix));
                if(check.ExecuteScalar() is long previous&&o.ObservedUtc.UtcTicks<previous)throw new InvalidDataException("Exposure time moved behind retained history.");
                using var clock=Command("INSERT INTO exposure_heads VALUES($n,$l,$s,$now) ON CONFLICT(node_id,ledger_id,scope) DO UPDATE SET observed_ticks=excluded.observed_ticks",tx,("$n",o.NodeId),("$l",o.LedgerId.ToString("D")),("$s",o.SubjectPrefix),("$now",o.ObservedUtc.UtcTicks));clock.ExecuteNonQuery();
            }
            var conditions = o.VerificationSucceeded ? o.Conditions : [new AlertCondition(o.Category==AlertCategory.Monitoring?HealthAlertPolicy.VerificationUnavailable:"ExposureDataUnavailable", AlertSeverity.Critical,o.SubjectPrefix)];
            var active = new List<ServerAlert>();
            using (var command = Command($"SELECT {Columns} FROM alerts WHERE node_id=$node AND ledger_id=$ledger AND category=$category AND substr(subject,1,length($prefix))=$prefix AND resolved_ticks IS NULL", tx,
                ("$node", o.NodeId), ("$ledger", o.LedgerId.ToString("D")),("$category",(int)o.Category),("$prefix",o.SubjectPrefix)))
            using (var reader = command.ExecuteReader()) while (reader.Read()) active.Add(ReadAlert(reader));
            foreach (var condition in conditions)
            {
                var existing = active.SingleOrDefault(a => a.Code == condition.Code&&a.Subject==condition.Subject);
                if(existing is not null&&o.Category==AlertCategory.Exposure&&!condition.PreserveExisting&&existing.Severity!=condition.Severity)
                {
                    // A fresh severity revision gets a new lifecycle so minimum-severity notification routes see escalation.
                    using var resolved=Command("UPDATE alerts SET resolved_ticks=$now WHERE id=$id",tx,("$now",o.ObservedUtc.UtcTicks),("$id",existing.Id));resolved.ExecuteNonQuery();
                    AddEvent(tx,existing.Id,AlertEventKind.Resolved,o.ObservedUtc,null);existing=null;
                }
                if (existing is not null)
                {
                    using var update = Command("UPDATE alerts SET last_ticks=$now WHERE id=$id", tx, ("$now", o.ObservedUtc.UtcTicks), ("$id", existing.Id));
                    update.ExecuteNonQuery(); continue;
                }
                if(condition.PreserveExisting)continue;
                using (var count = Command("SELECT COUNT(*) FROM alerts", tx))
                    if (Convert.ToInt64(count.ExecuteScalar()) >= _capacity) throw new InvalidOperationException("Alert history capacity reached.");
                using var insert = Command("""
                    INSERT INTO alerts(node_id,ledger_id,code,severity,opened_ticks,last_ticks,category,subject) VALUES($node,$ledger,$code,$severity,$now,$now,$category,$subject);
                    SELECT last_insert_rowid();
                    """, tx, ("$node", o.NodeId), ("$ledger", o.LedgerId.ToString("D")), ("$code", condition.Code),
                    ("$severity", (int)condition.Severity), ("$now", o.ObservedUtc.UtcTicks),("$category",(int)o.Category),("$subject",condition.Subject));
                long id = Convert.ToInt64(insert.ExecuteScalar()); AddEvent(tx, id, AlertEventKind.Opened, o.ObservedUtc, null);
            }
            if (o.VerificationSucceeded)
                foreach (var resolved in active.Where(a => !conditions.Any(c => c.Code == a.Code&&c.Subject==a.Subject)))
                {
                    using var update = Command("UPDATE alerts SET resolved_ticks=$now WHERE id=$id", tx, ("$now", o.ObservedUtc.UtcTicks), ("$id", resolved.Id));
                    update.ExecuteNonQuery(); AddEvent(tx, resolved.Id, AlertEventKind.Resolved, o.ObservedUtc, null);
                }
            cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
        }
        finally { _gate.Release(); }
    }
    public async Task<AlertPage> ReadAsync(AlertQuery query, CancellationToken cancellationToken = default)
    {
        if (query.Limit is < 1 or > 100 || query.BeforeId is < 1 || query.NodeId?.Length > 256
            || (query.NodeId is null) != (query.LedgerId is null) || query.LedgerId == Guid.Empty
            || (query.State is { } state && !Enum.IsDefined(state)) || (query.ActiveOnly && query.State == AlertState.Resolved))
            throw new ArgumentException("Invalid alert query.", nameof(query));
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var parameters = new List<(string, object)> { ("$limit", query.Limit + 1) }; var clauses = new List<string>();
            if (query.NodeId is not null) { clauses.Add("node_id=$node AND ledger_id=$ledger"); parameters.Add(("$node", query.NodeId)); parameters.Add(("$ledger", query.LedgerId!.Value.ToString("D"))); }
            if (query.BeforeId is { } before) { clauses.Add("id<$before"); parameters.Add(("$before", before)); }
            if (query.ActiveOnly) clauses.Add("resolved_ticks IS NULL");
            if (query.State is { } filter) clauses.Add(filter switch
            { AlertState.Open => "resolved_ticks IS NULL AND ack_ticks IS NULL", AlertState.Acknowledged => "resolved_ticks IS NULL AND ack_ticks IS NOT NULL", _ => "resolved_ticks IS NOT NULL" });
            string where = clauses.Count == 0 ? "" : "WHERE " + string.Join(" AND ", clauses);
            using var command = Command($"SELECT {Columns} FROM alerts {where} ORDER BY id DESC LIMIT $limit", null, parameters.ToArray());
            using var reader = command.ExecuteReader(); var alerts = new List<ServerAlert>();
            while (reader.Read()) { cancellationToken.ThrowIfCancellationRequested(); alerts.Add(ReadAlert(reader)); }
            bool more = alerts.Count > query.Limit; if (more) alerts.RemoveAt(alerts.Count - 1);
            return new(alerts.ToArray(), more ? alerts[^1].Id : null);
        }
        finally { _gate.Release(); }
    }
    public async Task<AlertCounts> CountAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var command = Command("SELECT COALESCE(SUM(resolved_ticks IS NULL AND ack_ticks IS NULL),0),COALESCE(SUM(resolved_ticks IS NULL AND ack_ticks IS NOT NULL),0),COALESCE(SUM(resolved_ticks IS NOT NULL),0) FROM alerts", null);
            using var reader = command.ExecuteReader(); reader.Read(); return new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2));
        }
        finally { _gate.Release(); }
    }
    public async Task<ServerAlert?> AcknowledgeAsync(long id, string actor, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (id < 1 || string.IsNullOrWhiteSpace(actor) || actor.Length > 128 || now.Offset != TimeSpan.Zero) throw new ArgumentException("Invalid acknowledgement.");
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(); ServerAlert? alert;
            using (var command = Command($"SELECT {Columns} FROM alerts WHERE id=$id", tx, ("$id", id)))
            using (var reader = command.ExecuteReader()) alert = reader.Read() ? ReadAlert(reader) : null;
            if (alert is null || alert.AcknowledgedUtc is not null || alert.ResolvedUtc is not null) return alert;
            if(alert.Category==AlertCategory.Monitoring)AdvanceClock(tx, alert.NodeId, alert.LedgerId, now);
            using var update = Command("UPDATE alerts SET ack_ticks=$now,ack_actor=$actor WHERE id=$id", tx, ("$now", now.UtcTicks), ("$actor", actor), ("$id", id));
            update.ExecuteNonQuery(); AddEvent(tx, id, AlertEventKind.Acknowledged, now, actor);
            cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
            return alert with { AcknowledgedUtc = now, AcknowledgedBy = actor };
        }
        finally { _gate.Release(); }
    }
    public async Task<AlertEvent[]> ReadEventsAsync(long alertId, CancellationToken cancellationToken = default)
    {
        if (alertId < 1) throw new ArgumentOutOfRangeException(nameof(alertId));
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var command = Command("SELECT id,kind,occurred_ticks,actor FROM alert_events WHERE alert_id=$id ORDER BY id LIMIT 4", null, ("$id", alertId));
            using var reader = command.ExecuteReader(); var events = new List<AlertEvent>();
            while (reader.Read()) events.Add(new(reader.GetInt64(0), alertId, (AlertEventKind)reader.GetInt32(1), Utc(reader.GetInt64(2)), reader.IsDBNull(3) ? null : reader.GetString(3)));
            if (events.Count > 3) throw new InvalidDataException("An alert has invalid duplicate transitions.");
            return events.ToArray();
        }
        finally { _gate.Release(); }
    }
    private void AdvanceClock(SqliteTransaction tx, string node, Guid ledger, DateTimeOffset now)
    {
        using (var check = Command("SELECT observed_ticks FROM observation_heads WHERE node_id=$node AND ledger_id=$ledger", tx, ("$node", node), ("$ledger", ledger.ToString("D"))))
            if (check.ExecuteScalar() is long previous && now.UtcTicks < previous) throw new InvalidDataException("Receiver time moved behind retained alert history.");
        using var update = Command("INSERT INTO observation_heads VALUES($node,$ledger,$now) ON CONFLICT(node_id,ledger_id) DO UPDATE SET observed_ticks=excluded.observed_ticks", tx,
            ("$node", node), ("$ledger", ledger.ToString("D")), ("$now", now.UtcTicks)); update.ExecuteNonQuery();
    }
    private void AddEvent(SqliteTransaction tx, long id, AlertEventKind kind, DateTimeOffset now, string? actor)
    {
        using var command = Command("INSERT INTO alert_events(alert_id,kind,occurred_ticks,actor) VALUES($id,$kind,$now,$actor)", tx,
            ("$id", id), ("$kind", (int)kind), ("$now", now.UtcTicks), ("$actor", (object?)actor ?? DBNull.Value)); command.ExecuteNonQuery();
        using var identity = Command("SELECT last_insert_rowid()", tx);
        long eventId = Convert.ToInt64(identity.ExecuteScalar());
        ServerAlert alert;
        using (var select = Command($"SELECT {Columns} FROM alerts WHERE id=$id", tx, ("$id", id)))
        using (var reader = select.ExecuteReader()) { if (!reader.Read()) throw new InvalidDataException("Missing alert transition subject."); alert = ReadAlert(reader); }
        using var document = Command("INSERT INTO alert_event_documents(event_id,document) VALUES($id,$document)", tx,
            ("$id", eventId), ("$document", AlertTransitionJson.Encode(new(new(eventId, id, kind, now, actor), alert))));
        document.ExecuteNonQuery();
    }
    private static ServerAlert ReadAlert(SqliteDataReader r) => new(r.GetInt64(0), r.GetString(1), Guid.ParseExact(r.GetString(2), "D"), r.GetString(3),
        (AlertSeverity)r.GetInt32(4), Utc(r.GetInt64(5)), Utc(r.GetInt64(6)), r.IsDBNull(7) ? null : Utc(r.GetInt64(7)),
        r.IsDBNull(8) ? null : r.GetString(8), r.IsDBNull(9) ? null : Utc(r.GetInt64(9)),(AlertCategory)r.GetInt32(10),r.GetString(11));
    private static DateTimeOffset Utc(long ticks) => new(ticks, TimeSpan.Zero);
    private const string Columns = "id,node_id,ledger_id,code,severity,opened_ticks,last_ticks,ack_ticks,ack_actor,resolved_ticks,category,subject";
    private SqliteCommand Command(string sql, SqliteTransaction? tx, params (string Name, object Value)[] values)
    {
        var command = _connection.CreateCommand(); command.Transaction = tx; command.CommandText = sql;
        foreach (var (name, value) in values) command.Parameters.AddWithValue(name, value); return command;
    }
    private async Task EnterAsync(CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        if (_disposed) { _gate.Release(); throw new ObjectDisposedException(nameof(SqliteAlertStore)); }
    }
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { if (_disposed) return; _disposed = true; try { _connection.Dispose(); } finally { _writer.Dispose(); } }
        finally { _gate.Release(); }
    }
}
