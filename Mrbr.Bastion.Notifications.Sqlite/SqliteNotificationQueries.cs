using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Alerting;

namespace Mrbr.Bastion.Notifications.Sqlite;

public sealed partial class SqliteNotificationQueue
{
    private const string SelectColumns = "sequence,id,route_id,feed_id,event_id,alert_id,node_id,ledger_id,event_kind,state,attempts,cycle_attempts,max_attempts,redrives,max_redrives,created_ticks,next_ticks,delivered_ticks,last_code,lease_until_ticks";
    private static DateTimeOffset Utc(long ticks) => new(ticks, TimeSpan.Zero);
    private static NotificationDelivery ReadDelivery(SqliteDataReader r) => new(r.GetInt64(0), Guid.ParseExact(r.GetString(1), "D"), r.GetString(2),
        Guid.ParseExact(r.GetString(3), "D"), r.GetInt64(4), r.GetInt64(5), r.GetString(6), Guid.ParseExact(r.GetString(7), "D"),
        (AlertEventKind)r.GetInt32(8), (NotificationState)r.GetInt32(9), r.GetInt32(10), r.GetInt32(11), r.GetInt32(12), r.GetInt32(13), r.GetInt32(14),
        Utc(r.GetInt64(15)), Utc(r.GetInt64(16)), r.IsDBNull(17) ? null : Utc(r.GetInt64(17)), r.IsDBNull(18) ? null : r.GetString(18), r.IsDBNull(19) ? null : Utc(r.GetInt64(19)));
    private NotificationDelivery? ReadById(Guid id, SqliteTransaction? tx)
    {
        using var command = Command($"SELECT {SelectColumns} FROM deliveries WHERE id=$id", tx, ("$id", id.ToString("D")));
        using var reader = command.ExecuteReader(); return reader.Read() ? ReadDelivery(reader) : null;
    }
    public async Task<NotificationPage> ReadAsync(NotificationQuery query, CancellationToken cancellationToken = default)
    {
        if (query.Limit is < 1 or > 100 || query.BeforeSequence is < 1 || query.AlertId is < 1 || query.RouteId?.Length > 64
            || query.State is { } state && !Enum.IsDefined(state)) throw new ArgumentException("Invalid notification query.");
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var where = new List<string>(); var parameters = new List<(string, object)> { ("$limit", query.Limit + 1) };
            if (query.State is { } filter) { where.Add("state=$state"); parameters.Add(("$state", (int)filter)); }
            if (query.RouteId is not null) { where.Add("route_id=$route"); parameters.Add(("$route", query.RouteId)); }
            if (query.BeforeSequence is { } before) { where.Add("sequence<$before"); parameters.Add(("$before", before)); }
            if (query.AlertId is { } alert) { where.Add("alert_id=$alert"); parameters.Add(("$alert", alert)); }
            using var command = Command($"SELECT {SelectColumns} FROM deliveries {(where.Count == 0 ? "" : "WHERE " + string.Join(" AND ", where))} ORDER BY sequence DESC LIMIT $limit", null, parameters.ToArray());
            using var reader = command.ExecuteReader(); var jobs = new List<NotificationDelivery>();
            while (reader.Read()) { cancellationToken.ThrowIfCancellationRequested(); jobs.Add(ReadDelivery(reader)); }
            bool more = jobs.Count > query.Limit; if (more) jobs.RemoveAt(jobs.Count - 1);
            return new(jobs.ToArray(), more ? jobs[^1].Sequence : null);
        }
        finally { _gate.Release(); }
    }
    public async Task<NotificationCounts> CountAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var command = Command("SELECT COALESCE(SUM(state=0),0),COALESCE(SUM(state=1),0),COALESCE(SUM(state=2),0),COALESCE(SUM(state=3),0) FROM deliveries", null);
            using var reader = command.ExecuteReader(); reader.Read(); return new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3));
        }
        finally { _gate.Release(); }
    }
    public async Task<NotificationDetail?> ReadDetailAsync(Guid id, CancellationToken cancellationToken = default)
    {
        if (id == Guid.Empty) throw new ArgumentException("Invalid delivery ID.");
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(deferred: true); var delivery = ReadById(id, tx); if (delivery is null) return null;
            var attempts = new List<NotificationAttempt>(); var actions = new List<NotificationRedrive>();
            using (var command = Command("SELECT id,number,started_ticks,completed_ticks,outcome,code,remote_status FROM attempts WHERE delivery_id=$id ORDER BY number LIMIT 276", tx, ("$id", id.ToString("D"))))
            using (var r = command.ExecuteReader()) while (r.Read()) attempts.Add(new(r.GetInt64(0), id, r.GetInt32(1), Utc(r.GetInt64(2)), r.IsDBNull(3) ? null : Utc(r.GetInt64(3)),
                (NotificationAttemptOutcome)r.GetInt32(4), r.IsDBNull(5) ? null : r.GetString(5), r.IsDBNull(6) ? null : r.GetInt32(6)));
            using (var command = Command("SELECT id,requested_ticks,actor FROM redrives WHERE delivery_id=$id ORDER BY id LIMIT 11", tx, ("$id", id.ToString("D"))))
            using (var r = command.ExecuteReader()) while (r.Read()) actions.Add(new(r.GetInt64(0), id, Utc(r.GetInt64(1)), r.GetString(2)));
            if (attempts.Count > 275 || actions.Count > 10) throw new InvalidDataException("Invalid notification attempt history.");
            return new(delivery, attempts.ToArray(), actions.ToArray());
        }
        finally { _gate.Release(); }
    }
}
