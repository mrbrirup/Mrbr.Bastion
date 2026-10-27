using Microsoft.Data.Sqlite;

namespace Mrbr.Bastion.Alerting.Sqlite;

public sealed partial class SqliteAlertStore
{
    private Guid _feedId;
    public async Task<AlertFeedPosition> ReadPositionAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try { using var tx = _connection.BeginTransaction(deferred: true); return ReadPosition(tx); }
        finally { _gate.Release(); }
    }
    private AlertFeedPosition ReadPosition(SqliteTransaction tx)
    {
        using var command = Command("SELECT feed_id,(SELECT COALESCE(MAX(id),0) FROM alert_events) FROM alert_feed WHERE singleton=1", tx);
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetString(0) != _feedId.ToString("D")) throw new InvalidDataException("The alert feed identity changed.");
        return new(_feedId, reader.GetInt64(1));
    }
    public async Task<AlertFeedPage> ReadChangesAsync(long afterEventId, int limit = 100, CancellationToken cancellationToken = default)
    {
        if (afterEventId < 0 || limit is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(afterEventId));
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var tx = _connection.BeginTransaction(deferred: true); var position = ReadPosition(tx);
            if (afterEventId > position.LastEventId) throw new InvalidDataException("The retained alert feed moved behind its consumer.");
            using var command = Command("""
                SELECT e.id,e.alert_id,e.kind,e.occurred_ticks,e.actor,d.document FROM alert_events e
                LEFT JOIN alert_event_documents d ON d.event_id=e.id WHERE e.id>$after ORDER BY e.id LIMIT $limit
                """, tx, ("$after", afterEventId), ("$limit", limit));
            using var reader = command.ExecuteReader(); var changes = new List<AlertTransition>();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (reader.IsDBNull(5) || reader.GetBytes(5, 0, null, 0, 0) > AlertTransitionJson.MaximumBytes) throw new InvalidDataException("Missing or oversized alert transition snapshot.");
                var change = AlertTransitionJson.Decode(reader.GetFieldValue<byte[]>(5)); var e = change.Event;
                if (e.Id != reader.GetInt64(0) || e.AlertId != reader.GetInt64(1) || (int)e.Kind != reader.GetInt32(2)
                    || e.OccurredUtc.UtcTicks != reader.GetInt64(3) || e.Actor != (reader.IsDBNull(4) ? null : reader.GetString(4)))
                    throw new InvalidDataException("The alert transition differs from its retained metadata.");
                changes.Add(change);
            }
            return new(position, changes.ToArray());
        }
        finally { _gate.Release(); }
    }
    private static void MigrateEventFeed(SqliteConnection connection)
    {
        using var tx = connection.BeginTransaction();
        using var create = connection.CreateCommand(); create.Transaction = tx;
        create.CommandText = """
            CREATE TABLE alert_feed(singleton INTEGER PRIMARY KEY CHECK(singleton=1),feed_id TEXT NOT NULL);
            CREATE TABLE alert_event_documents(event_id INTEGER PRIMARY KEY REFERENCES alert_events(id),document BLOB NOT NULL);
            INSERT INTO alert_feed VALUES(1,$feed);
            """;
        create.Parameters.AddWithValue("$feed", Guid.NewGuid().ToString("D")); create.ExecuteNonQuery();
        long after = 0;
        while (true)
        {
            var page = new List<AlertTransition>();
            using (var select = connection.CreateCommand())
            {
                select.Transaction = tx;
                select.CommandText = """
                    SELECT e.id,e.kind,e.occurred_ticks,e.actor,a.id,a.node_id,a.ledger_id,a.code,a.severity,a.opened_ticks,a.last_ticks,a.ack_ticks,a.ack_actor,a.resolved_ticks
                    FROM alert_events e JOIN alerts a ON a.id=e.alert_id WHERE e.id>$after ORDER BY e.id LIMIT 100
                    """;
                select.Parameters.AddWithValue("$after", after); using var r = select.ExecuteReader();
                while (r.Read())
                {
                    long id = r.GetInt64(0); var kind = (AlertEventKind)r.GetInt32(1); var occurred = Utc(r.GetInt64(2));
                    string? actor = r.IsDBNull(3) ? null : r.GetString(3);
                    DateTimeOffset? ack = kind == AlertEventKind.Opened || r.IsDBNull(11) ? null : Utc(r.GetInt64(11));
                    var alert = new ServerAlert(r.GetInt64(4), r.GetString(5), Guid.ParseExact(r.GetString(6), "D"), r.GetString(7), (AlertSeverity)r.GetInt32(8),
                        Utc(r.GetInt64(9)), kind == AlertEventKind.Opened ? Utc(r.GetInt64(9)) : Utc(Math.Min(r.GetInt64(10), occurred.UtcTicks)),
                        ack, ack is null ? null : r.GetString(12), kind == AlertEventKind.Resolved ? occurred : null);
                    page.Add(new(new(id, alert.Id, kind, occurred, actor), alert, Reconstructed: true));
                }
            }
            foreach (var item in page)
            {
                using var insert = connection.CreateCommand(); insert.Transaction = tx;
                insert.CommandText = "INSERT INTO alert_event_documents VALUES($id,$document)";
                insert.Parameters.AddWithValue("$id", item.Event.Id); insert.Parameters.AddWithValue("$document", AlertTransitionJson.Encode(item));
                insert.ExecuteNonQuery(); after = item.Event.Id;
            }
            if (page.Count < 100) break;
        }
        using var version = connection.CreateCommand(); version.Transaction = tx;
        version.CommandText = "UPDATE alert_metadata SET version=2 WHERE singleton=1"; version.ExecuteNonQuery(); tx.Commit();
    }
}
