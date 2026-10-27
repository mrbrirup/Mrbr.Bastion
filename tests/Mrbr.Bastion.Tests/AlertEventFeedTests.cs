using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Alerting.Sqlite;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class AlertEventFeedTests
{
    [Fact]
    public async Task TransitionSnapshotsDoNotChangeWhenTheLiveAlertIsPolledAcknowledgedOrResolved()
    {
        await using var f = await NotificationFixture.CreateAsync(includeAcknowledgements: true);
        await f.ObserveAsync("Offline"); var opened = Assert.Single((await f.Operations.Alerts.ReadChangesAsync(0)).Changes);
        f.Clock.Advance(TimeSpan.FromSeconds(1)); await f.ObserveAsync("Offline");
        await f.Operations.Alerts.AcknowledgeAsync(opened.Alert.Id, "operator", f.Clock.GetUtcNow());
        f.Clock.Advance(TimeSpan.FromSeconds(1)); await f.ObserveAsync();
        var all = await f.Operations.Alerts.ReadChangesAsync(0);
        Assert.Equal(3, all.Changes.Length); Assert.All(all.Changes, change => Assert.False(change.Reconstructed)); Assert.Equal(AlertState.Open, all.Changes[0].Alert.State);
        Assert.Null(all.Changes[0].Alert.AcknowledgedUtc); Assert.Null(all.Changes[0].Alert.ResolvedUtc);
        Assert.Equal(AlertState.Acknowledged, all.Changes[1].Alert.State); Assert.Equal(AlertState.Resolved, all.Changes[2].Alert.State);
        Assert.Equal(AlertTransitionJson.Encode(opened), AlertTransitionJson.Encode(all.Changes[0]));
        Assert.Equal(all.Position, await f.Operations.Alerts.ReadPositionAsync());
    }
    [Fact]
    public async Task EventJournalFailureRollsBackTheAlertAndObservationHead()
    {
        await using var f = await NotificationFixture.CreateAsync();
        Execute(f, "CREATE TRIGGER fail_journal BEFORE INSERT ON alert_event_documents BEGIN SELECT RAISE(FAIL,'test journal failure'); END");
        await Assert.ThrowsAsync<SqliteException>(() => f.ObserveAsync("Offline"));
        Assert.Equal(0, (await f.Operations.Alerts.CountAsync()).Open);
        Assert.Equal(0, (await f.Operations.Alerts.ReadPositionAsync()).LastEventId);
        Execute(f, "DROP TRIGGER fail_journal"); f.Clock.Advance(TimeSpan.FromSeconds(-1));
        await f.ObserveAsync("Offline"); Assert.Single((await f.Operations.Alerts.ReadChangesAsync(0)).Changes);
    }
    [Fact]
    public async Task ExistingVersionOneDatabasesMigrateWithoutLosingAlertHistory()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline");
        var alert = Assert.Single((await f.Operations.Alerts.ReadAsync(new())).Alerts);
        f.Clock.Advance(TimeSpan.FromSeconds(1)); await f.Operations.Alerts.AcknowledgeAsync(alert.Id, "operator", f.Clock.GetUtcNow());
        f.Clock.Advance(TimeSpan.FromSeconds(1)); await f.ObserveAsync();
        await f.Operations.Alerts.DisposeAsync();
        Execute(f, "DROP TABLE alert_event_documents; DROP TABLE alert_feed; DROP TABLE exposure_heads; DROP INDEX one_active_condition; ALTER TABLE alerts DROP COLUMN category; ALTER TABLE alerts DROP COLUMN subject; CREATE UNIQUE INDEX one_active_condition ON alerts(node_id,ledger_id,code) WHERE resolved_ticks IS NULL; UPDATE alert_metadata SET version=1");
        await using var migrated = await SqliteAlertStore.OpenAsync(new() { DatabasePath = f.Operations.DatabasePath });
        var page = await migrated.ReadChangesAsync(0);
        Assert.Equal([AlertEventKind.Opened, AlertEventKind.Acknowledged, AlertEventKind.Resolved], page.Changes.Select(c => c.Event.Kind));
        Assert.Equal(1, (await migrated.CountAsync()).Resolved); Assert.All(page.Changes, change => Assert.True(change.Reconstructed)); Assert.Null(page.Changes[0].Alert.AcknowledgedUtc);
        var position = page.Position; await migrated.DisposeAsync();
        await using var reopened = await SqliteAlertStore.OpenAsync(new() { DatabasePath = f.Operations.DatabasePath });
        Assert.Equal(position, await reopened.ReadPositionAsync());
    }
    [Fact]
    public async Task MissingSnapshotsAndRewoundFeedPositionsAreRejectedRatherThanSkipped()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline");
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Operations.Alerts.ReadChangesAsync(100));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => f.Operations.Alerts.ReadChangesAsync(0, 101));
        Execute(f, "DELETE FROM alert_event_documents WHERE event_id=1");
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Operations.Alerts.ReadChangesAsync(0));
    }
    private static void Execute(NotificationFixture f, string sql)
    {
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.Operations.DatabasePath, Pooling = false }.ToString()); db.Open();
        using var command = db.CreateCommand(); command.CommandText = sql; command.ExecuteNonQuery();
    }
}
