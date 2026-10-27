using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Alerting;

namespace Mrbr.Bastion.Notifications.Sqlite;

public sealed record SqliteNotificationOptions
{
    public required string DatabasePath { get; init; }
    public int MaximumStoredDeliveries { get; init; } = 100000;
    public long MaximumReservedBytes { get; init; } = 1024L * 1024 * 1024;
    public int MaximumManualRedrives { get; init; } = 3;
}

/// <summary>Durable subscriptions and delivery attempts. External acceptance and a local commit cannot form one transaction.</summary>
public sealed partial class SqliteNotificationQueue : INotificationQueue
{
    private readonly SqliteConnection _connection;
    private readonly FileStream _writer;
    private readonly SqliteNotificationOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _disposed;
    private SqliteNotificationQueue(SqliteConnection connection, FileStream writer, SqliteNotificationOptions options)
    { _connection = connection; _writer = writer; _options = options; }
    public static Task<SqliteNotificationQueue> OpenAsync(SqliteNotificationOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options); ArgumentException.ThrowIfNullOrWhiteSpace(options.DatabasePath);
        if (options.MaximumStoredDeliveries is < 1 or > 10000000 || options.MaximumReservedBytes < 1048576
            || options.MaximumManualRedrives is < 0 or > 10) throw new ArgumentOutOfRangeException(nameof(options));
        cancellationToken.ThrowIfCancellationRequested(); string path = Path.GetFullPath(options.DatabasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var writer = new FileStream(path + ".writer.lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        SqliteConnection? connection = null;
        try
        {
            bool exists = File.Exists(path);
            connection = new(new SqliteConnectionStringBuilder { DataSource = path, Mode = exists ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString());
            connection.Open(); using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;"; command.ExecuteNonQuery();
            if (!exists) Initialize(connection);
            command.CommandText = "PRAGMA quick_check";
            if (command.ExecuteScalar() as string != "ok") throw new InvalidDataException("Notification database integrity check failed.");
            command.CommandText = "SELECT version FROM notification_metadata WHERE singleton=1";
            if (Convert.ToInt32(command.ExecuteScalar()) != 1) throw new InvalidDataException("Unsupported notification schema.");
            command.CommandText = "PRAGMA foreign_key_check";
            using (var reader = command.ExecuteReader()) if (reader.Read()) throw new InvalidDataException("Notification history references missing records.");
            return Task.FromResult(new SqliteNotificationQueue(connection, writer, options));
        }
        catch { connection?.Dispose(); writer.Dispose(); throw; }
    }
    public async Task RegisterAsync(NotificationRoute route, AlertFeedPosition position, CancellationToken cancellationToken = default)
    {
        route.Validate();
        if (position.FeedId == Guid.Empty || position.LastEventId < 0) throw new ArgumentException("Invalid alert feed position.");
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction();
            using (var source = Command("SELECT feed_id FROM notification_metadata WHERE singleton=1", tx))
            {
                if (source.ExecuteScalar() is string feed && feed != position.FeedId.ToString("D")) throw new NotificationConflictException("AlertFeedIdentityChanged");
            }
            using (var bind = Command("UPDATE notification_metadata SET feed_id=$feed WHERE singleton=1 AND feed_id IS NULL", tx, ("$feed", position.FeedId.ToString("D")))) bind.ExecuteNonQuery();
            var existing = ReadSubscription(route.Id, tx);
            if (existing is not null)
            {
                if (existing.Route.Fingerprint != route.Fingerprint || existing.Route.MinimumSeverity != route.MinimumSeverity
                    || existing.Route.IncludeAcknowledgements != route.IncludeAcknowledgements) throw new NotificationConflictException("RouteIdAlreadyBindsAnotherDestinationOrFilter");
                if (existing.Cursor > position.LastEventId) throw new InvalidDataException("The alert feed moved behind its notification cursor.");
                return;
            }
            using (var count = Command("SELECT COUNT(*) FROM subscriptions", tx))
                if (Convert.ToInt64(count.ExecuteScalar()) >= 1000) throw new InvalidOperationException("Notification subscription capacity reached.");
            using var insert = Command("INSERT INTO subscriptions(route_id,fingerprint,feed_id,cursor,minimum_severity,include_ack,replay) VALUES($id,$fingerprint,$feed,$cursor,$severity,$ack,$replay)", tx,
                ("$id", route.Id), ("$fingerprint", route.Fingerprint), ("$feed", position.FeedId.ToString("D")),
                ("$cursor", route.ReplayExistingEvents ? 0 : position.LastEventId), ("$severity", (int)route.MinimumSeverity), ("$ack", route.IncludeAcknowledgements), ("$replay", route.ReplayExistingEvents));
            insert.ExecuteNonQuery(); cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
        }
        finally { _gate.Release(); }
    }
    public async Task<NotificationSubscription> ReadSubscriptionAsync(string routeId, CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try { return ReadSubscription(routeId, null) ?? throw new KeyNotFoundException("Unknown notification subscription."); }
        finally { _gate.Release(); }
    }
    private NotificationSubscription? ReadSubscription(string id, SqliteTransaction? tx)
    {
        using var command = Command("SELECT fingerprint,feed_id,cursor,minimum_severity,include_ack,replay FROM subscriptions WHERE route_id=$id", tx, ("$id", id));
        using var r = command.ExecuteReader();
        return r.Read() ? new(new(id, r.GetString(0), r.GetBoolean(5), (AlertSeverity)r.GetInt32(3), r.GetBoolean(4)), Guid.ParseExact(r.GetString(1), "D"), r.GetInt64(2)) : null;
    }
    public async Task AppendAsync(NotificationRoute route, long expectedCursor, AlertFeedPage page, DateTimeOffset now,
        int maximumAttempts, CancellationToken cancellationToken = default)
    {
        route.Validate(); ValidateUtc(now);
        if (maximumAttempts is < 1 or > 25 || expectedCursor < 0 || page.Position.LastEventId < expectedCursor || page.Changes.Length > 100)
            throw new ArgumentException("Invalid notification routing batch.");
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(); AdvanceClock(tx, now);
            var subscription = ReadSubscription(route.Id, tx) ?? throw new KeyNotFoundException("Unknown notification subscription.");
            if (subscription.Route.Fingerprint != route.Fingerprint || subscription.FeedId != page.Position.FeedId
                || subscription.Route.MinimumSeverity != route.MinimumSeverity || subscription.Route.IncludeAcknowledgements != route.IncludeAcknowledgements)
                throw new NotificationConflictException("NotificationRouteBindingMismatch");
            if (subscription.Cursor != expectedCursor) throw new NotificationConflictException("NotificationCursorChanged");
            long cursor = expectedCursor;
            foreach (var change in page.Changes)
            {
                AlertTransitionJson.Validate(change);
                if (change.Event.Id <= cursor || change.Event.Id > page.Position.LastEventId) throw new InvalidDataException("Invalid alert event ordering.");
                cursor = change.Event.Id;
                if (!route.Matches(change)) continue;
                Guid id = Guid.NewGuid(); byte[] body = NotificationJson.Encode(new(1, id, subscription.FeedId, route.Id, change));
                long reserve = body.Length + 4096L + maximumAttempts * (1L + _options.MaximumManualRedrives) * 1024L;
                using (var capacity = Command("SELECT COUNT(*),COALESCE(SUM(reserved_bytes),0) FROM deliveries", tx))
                using (var reader = capacity.ExecuteReader())
                {
                    reader.Read();
                    if (reader.GetInt64(0) >= _options.MaximumStoredDeliveries || reader.GetInt64(1) > _options.MaximumReservedBytes - reserve)
                        throw new InvalidOperationException("Notification history capacity reached; the alert feed cursor was not advanced.");
                }
                var a = change.Alert;
                using var insert = Command("""
                    INSERT INTO deliveries(id,route_id,feed_id,event_id,alert_id,node_id,ledger_id,event_kind,state,attempts,cycle_attempts,max_attempts,redrives,max_redrives,
                        created_ticks,next_ticks,body,body_hash,reserved_bytes)
                    VALUES($id,$route,$feed,$event,$alert,$node,$ledger,$kind,0,0,0,$max,0,$redrives,$now,$now,$body,$hash,$reserved)
                    """, tx, ("$id", id.ToString("D")), ("$route", route.Id), ("$feed", subscription.FeedId.ToString("D")),
                    ("$event", change.Event.Id), ("$alert", a.Id), ("$node", a.NodeId), ("$ledger", a.LedgerId.ToString("D")), ("$kind", (int)change.Event.Kind),
                    ("$max", maximumAttempts), ("$redrives", _options.MaximumManualRedrives), ("$now", now.UtcTicks),
                    ("$body", body), ("$hash", Convert.ToHexString(SHA256.HashData(body))), ("$reserved", reserve));
                insert.ExecuteNonQuery();
            }
            if (page.Changes.Length == 0 && expectedCursor != page.Position.LastEventId) throw new InvalidDataException("The alert feed returned no evidence for its high-water mark.");
            using var update = Command("UPDATE subscriptions SET cursor=$cursor WHERE route_id=$route", tx, ("$cursor", cursor), ("$route", route.Id)); update.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
        }
        finally { _gate.Release(); }
    }
    public async Task<NotificationLease?> LeaseAsync(IReadOnlyCollection<string> activeRouteIds, DateTimeOffset now, TimeSpan duration, CancellationToken cancellationToken = default)
    {
        ValidateUtc(now);
        if (activeRouteIds.Count > 1000 || duration < TimeSpan.FromSeconds(5) || duration > TimeSpan.FromMinutes(10)) throw new ArgumentOutOfRangeException(nameof(duration));
        if (activeRouteIds.Count == 0) return null;
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(); AdvanceClock(tx, now);
            var parameters = new List<(string, object)> { ("$now", now.UtcTicks) }; var names = new List<string>();
            foreach (string route in activeRouteIds) { string name = "$route" + names.Count; names.Add(name); parameters.Add((name, route)); }
            for (int recoveries = 0; recoveries < 100; recoveries++)
            {
                NotificationDelivery? delivery;
                using (var select = Command($"""
                    SELECT {SelectColumns} FROM deliveries d WHERE route_id IN ({string.Join(',', names)})
                    AND ((state=0 AND next_ticks<=$now) OR (state=1 AND lease_until_ticks<=$now))
                    AND NOT EXISTS(SELECT 1 FROM deliveries p WHERE p.route_id=d.route_id AND p.feed_id=d.feed_id AND p.alert_id=d.alert_id AND p.sequence<d.sequence AND p.state IN(0,1))
                    ORDER BY sequence LIMIT 1
                    """, tx, parameters.ToArray()))
                using (var reader = select.ExecuteReader()) delivery = reader.Read() ? ReadDelivery(reader) : null;
                if (delivery is null) { cancellationToken.ThrowIfCancellationRequested(); tx.Commit(); return null; }
                string id = delivery.Id.ToString("D");
                if (delivery.State == NotificationState.InFlight)
                {
                    using var expired = Command("UPDATE attempts SET outcome=4,completed_ticks=$now,code='DeliveryOutcomeUnknown' WHERE delivery_id=$id AND number=$number AND outcome=0", tx,
                        ("$now", now.UtcTicks), ("$id", id), ("$number", delivery.Attempts));
                    if (expired.ExecuteNonQuery() != 1) throw new InvalidDataException("Missing in-flight notification attempt.");
                }
                if (delivery.CycleAttempts >= delivery.MaximumAttempts)
                {
                    using var terminal = Command("UPDATE deliveries SET state=3,last_code='AttemptLimitAfterLeaseExpiry',lease_token=NULL,lease_until_ticks=NULL WHERE id=$id", tx, ("$id", id));
                    terminal.ExecuteNonQuery(); continue;
                }
                byte[] body;
                using (var content = Command("SELECT body,body_hash FROM deliveries WHERE id=$id", tx, ("$id", id)))
                using (var reader = content.ExecuteReader())
                {
                    if (!reader.Read() || reader.GetBytes(0, 0, null, 0, 0) > NotificationJson.MaximumBytes) throw new InvalidDataException("Missing or oversized notification body.");
                    body = reader.GetFieldValue<byte[]>(0);
                    if (Convert.ToHexString(SHA256.HashData(body)) != reader.GetString(1)) throw new InvalidDataException("Notification content hash mismatch.");
                    var message = NotificationJson.Decode(body);
                    if (message.DeliveryId != delivery.Id || message.RouteId != delivery.RouteId || message.AlertFeedId != delivery.FeedId
                        || message.Transition.Event.Id != delivery.EventId || message.Transition.Alert.Id != delivery.AlertId
                        || message.Transition.Alert.NodeId != delivery.NodeId || message.Transition.Alert.LedgerId != delivery.LedgerId
                        || message.Transition.Event.Kind != delivery.EventKind) throw new InvalidDataException("Notification body does not match its durable identity.");
                }
                Guid token = Guid.NewGuid(); var expires = now + duration;
                using (var update = Command("UPDATE deliveries SET state=1,attempts=attempts+1,cycle_attempts=cycle_attempts+1,lease_token=$token,lease_until_ticks=$expires WHERE id=$id", tx,
                    ("$token", token.ToString("D")), ("$expires", expires.UtcTicks), ("$id", id))) update.ExecuteNonQuery();
                using (var insert = Command("INSERT INTO attempts(delivery_id,number,started_ticks,outcome) VALUES($id,$number,$now,0)", tx,
                    ("$id", id), ("$number", delivery.Attempts + 1), ("$now", now.UtcTicks))) insert.ExecuteNonQuery();
                cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
                return new(delivery with { State = NotificationState.InFlight, Attempts = delivery.Attempts + 1,
                    CycleAttempts = delivery.CycleAttempts + 1, LeaseExpiresUtc = expires }, token, expires, body);
            }
            cancellationToken.ThrowIfCancellationRequested(); tx.Commit(); return null;
        }
        finally { _gate.Release(); }
    }
    public async Task CompleteAsync(NotificationLease lease, NotificationResult result, DateTimeOffset now, DateTimeOffset nextAttemptUtc, CancellationToken cancellationToken = default)
    {
        ValidateUtc(now); ValidateUtc(nextAttemptUtc);
        if (!Enum.IsDefined(result.Disposition) || string.IsNullOrEmpty(result.Code) || result.Code.Length > 64
            || result.Code.Any(c => !char.IsAsciiLetterOrDigit(c)) || result.RemoteStatus is < 100 or > 599
            || nextAttemptUtc < now || nextAttemptUtc > now.AddDays(1)) throw new ArgumentException("Invalid notification outcome.");
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(); AdvanceClock(tx, now);
            var delivery = ReadById(lease.Delivery.Id, tx) ?? throw new KeyNotFoundException();
            using (var current = Command("SELECT lease_token,lease_until_ticks FROM deliveries WHERE id=$id", tx, ("$id", delivery.Id.ToString("D"))))
            using (var reader = current.ExecuteReader())
                if (!reader.Read() || delivery.State != NotificationState.InFlight || reader.IsDBNull(0) || reader.GetString(0) != lease.Token.ToString("D")
                    || now.UtcTicks >= reader.GetInt64(1) || delivery.Attempts != lease.Delivery.Attempts) throw new NotificationConflictException("NotificationLeaseLost");
            var state = result.Disposition switch { NotificationDisposition.Accepted => NotificationState.Delivered,
                NotificationDisposition.PermanentFailure => NotificationState.DeadLetter,
                _ => delivery.CycleAttempts >= delivery.MaximumAttempts ? NotificationState.DeadLetter : NotificationState.Pending };
            var outcome = result.Disposition switch { NotificationDisposition.Accepted => NotificationAttemptOutcome.Accepted,
                NotificationDisposition.PermanentFailure => NotificationAttemptOutcome.PermanentFailure, _ => NotificationAttemptOutcome.Retry };
            string id = delivery.Id.ToString("D");
            using (var attempt = Command("UPDATE attempts SET completed_ticks=$now,outcome=$outcome,code=$code,remote_status=$remote WHERE delivery_id=$id AND number=$number AND outcome=0", tx,
                ("$now", now.UtcTicks), ("$outcome", (int)outcome), ("$code", result.Code), ("$remote", (object?)result.RemoteStatus ?? DBNull.Value), ("$id", id), ("$number", delivery.Attempts)))
                if (attempt.ExecuteNonQuery() != 1) throw new InvalidDataException("Missing notification attempt.");
            using (var update = Command("UPDATE deliveries SET state=$state,next_ticks=$next,delivered_ticks=$delivered,last_code=$code,lease_token=NULL,lease_until_ticks=NULL WHERE id=$id", tx,
                ("$state", (int)state), ("$next", nextAttemptUtc.UtcTicks), ("$delivered", state == NotificationState.Delivered ? now.UtcTicks : DBNull.Value), ("$code", result.Code), ("$id", id))) update.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
        }
        finally { _gate.Release(); }
    }
    public async Task<NotificationDelivery?> RedriveAsync(Guid id, string actor, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ValidateUtc(now);
        if (id == Guid.Empty || string.IsNullOrWhiteSpace(actor) || actor.Length > 128) throw new ArgumentException("Invalid notification retry.");
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(); var delivery = ReadById(id, tx);
            if (delivery is null || delivery.State != NotificationState.DeadLetter) return delivery;
            if (delivery.Redrives >= delivery.MaximumRedrives) throw new NotificationConflictException("ManualRetryLimitReached");
            AdvanceClock(tx, now);
            using (var update = Command("UPDATE deliveries SET state=0,cycle_attempts=0,redrives=redrives+1,next_ticks=$now,last_code='OperatorRetryRequested' WHERE id=$id", tx,
                ("$id", id.ToString("D")), ("$now", now.UtcTicks))) update.ExecuteNonQuery();
            using (var action = Command("INSERT INTO redrives(delivery_id,requested_ticks,actor) VALUES($id,$now,$actor)", tx,
                ("$id", id.ToString("D")), ("$now", now.UtcTicks), ("$actor", actor))) action.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
            return delivery with { State = NotificationState.Pending, CycleAttempts = 0, Redrives = delivery.Redrives + 1, NextAttemptUtc = now, LastCode = "OperatorRetryRequested" };
        }
        finally { _gate.Release(); }
    }
    private void AdvanceClock(SqliteTransaction tx, DateTimeOffset now)
    {
        using (var command = Command("SELECT last_ticks FROM notification_metadata WHERE singleton=1", tx))
            if (command.ExecuteScalar() is long previous && now.UtcTicks < previous) throw new InvalidDataException("Receiver time moved behind retained notification state.");
        using var update = Command("UPDATE notification_metadata SET last_ticks=$now WHERE singleton=1", tx, ("$now", now.UtcTicks)); update.ExecuteNonQuery();
    }
    private static void ValidateUtc(DateTimeOffset now) { if (now.Offset != TimeSpan.Zero) throw new ArgumentException("UTC time is required."); }
    private SqliteCommand Command(string sql, SqliteTransaction? tx, params (string Name, object Value)[] values)
    {
        var command = _connection.CreateCommand(); command.Transaction = tx; command.CommandText = sql;
        foreach (var (name, value) in values) command.Parameters.AddWithValue(name, value); return command;
    }
    private async Task EnterAsync(CancellationToken token)
    { await _gate.WaitAsync(token).ConfigureAwait(false); if (_disposed) { _gate.Release(); throw new ObjectDisposedException(nameof(SqliteNotificationQueue)); } }
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { if (_disposed) return; _disposed = true; try { _connection.Dispose(); } finally { _writer.Dispose(); } }
        finally { _gate.Release(); }
    }
    private static void Initialize(SqliteConnection connection)
    {
        using var tx = connection.BeginTransaction(); using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = """
            CREATE TABLE notification_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,feed_id TEXT,last_ticks INTEGER NOT NULL);
            INSERT INTO notification_metadata VALUES(1,1,NULL,0);
            CREATE TABLE subscriptions(route_id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,feed_id TEXT NOT NULL,cursor INTEGER NOT NULL CHECK(cursor>=0),
                minimum_severity INTEGER NOT NULL,include_ack INTEGER NOT NULL,replay INTEGER NOT NULL);
            CREATE TABLE deliveries(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,route_id TEXT NOT NULL REFERENCES subscriptions(route_id),feed_id TEXT NOT NULL,
                event_id INTEGER NOT NULL,alert_id INTEGER NOT NULL,node_id TEXT NOT NULL,ledger_id TEXT NOT NULL,event_kind INTEGER NOT NULL,
                state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3),attempts INTEGER NOT NULL,cycle_attempts INTEGER NOT NULL,max_attempts INTEGER NOT NULL,
                redrives INTEGER NOT NULL,max_redrives INTEGER NOT NULL,created_ticks INTEGER NOT NULL,next_ticks INTEGER NOT NULL,delivered_ticks INTEGER,
                last_code TEXT,lease_token TEXT,lease_until_ticks INTEGER,body BLOB NOT NULL,body_hash TEXT NOT NULL,reserved_bytes INTEGER NOT NULL,
                UNIQUE(route_id,feed_id,event_id),CHECK((state=1 AND lease_token IS NOT NULL AND lease_until_ticks IS NOT NULL) OR (state<>1 AND lease_token IS NULL AND lease_until_ticks IS NULL)));
            CREATE INDEX due_notifications ON deliveries(state,next_ticks,lease_until_ticks);
            CREATE INDEX notification_alert_order ON deliveries(route_id,feed_id,alert_id,sequence);
            CREATE TABLE attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,delivery_id TEXT NOT NULL REFERENCES deliveries(id),number INTEGER NOT NULL,
                started_ticks INTEGER NOT NULL,completed_ticks INTEGER,outcome INTEGER NOT NULL CHECK(outcome BETWEEN 0 AND 4),code TEXT,remote_status INTEGER,UNIQUE(delivery_id,number));
            CREATE TABLE redrives(id INTEGER PRIMARY KEY AUTOINCREMENT,delivery_id TEXT NOT NULL REFERENCES deliveries(id),requested_ticks INTEGER NOT NULL,actor TEXT NOT NULL);
            """;
        command.ExecuteNonQuery(); tx.Commit();
    }
}
