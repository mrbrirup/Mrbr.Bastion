using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Alerting.Sqlite;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class AlertStoreTests
{
    private static AlertObservation Observe(OperationsFixture f, string[] codes, bool success = true) =>
        new(f.NodeId, f.LedgerId, f.Audits.Clock.GetUtcNow(), codes.Select(c => new AlertCondition(c, AlertSeverity.Warning)).ToArray(), success);
    [Fact]
    public async Task PollingDeduplicatesAndAcknowledgementDoesNotResolveAnActiveCondition()
    {
        await using var f = await OperationsFixture.CreateAsync();
        await f.Alerts.ApplyAsync(Observe(f, ["StaleHeartbeat"])); f.Audits.Clock.Advance(TimeSpan.FromSeconds(1));
        await f.Alerts.ApplyAsync(Observe(f, ["StaleHeartbeat"]));
        var alert = Assert.Single((await f.Alerts.ReadAsync(new())).Alerts); Assert.Equal(AlertState.Open, alert.State);
        Assert.True(alert.LastObservedUtc > alert.OpenedUtc);
        var ack = await f.Alerts.AcknowledgeAsync(alert.Id, "alice", f.Audits.Clock.GetUtcNow()); Assert.Equal(AlertState.Acknowledged, ack!.State);
        var retry = await f.Alerts.AcknowledgeAsync(alert.Id, "bob", f.Audits.Clock.GetUtcNow().AddSeconds(1)); Assert.Equal(ack, retry);
        await f.Alerts.ApplyAsync(Observe(f, ["StaleHeartbeat"])); Assert.Single((await f.Alerts.ReadAsync(new(ActiveOnly: true))).Alerts);
        Assert.Equal(2, (await f.Alerts.ReadEventsAsync(alert.Id)).Length);
        Assert.Equal(new AlertCounts(0, 1, 0), await f.Alerts.CountAsync());
    }
    [Fact]
    public async Task RecoveryResolvesAndRecurrenceCreatesANewAlertWithSeparateHistory()
    {
        await using var f = await OperationsFixture.CreateAsync(); await f.Alerts.ApplyAsync(Observe(f, ["Offline"]));
        long first = Assert.Single((await f.Alerts.ReadAsync(new())).Alerts).Id;
        await f.Alerts.AcknowledgeAsync(first, "operator", f.Audits.Clock.GetUtcNow());
        f.Audits.Clock.Advance(TimeSpan.FromSeconds(1)); await f.Alerts.ApplyAsync(Observe(f, []));
        var resolved = Assert.Single((await f.Alerts.ReadAsync(new(State: AlertState.Resolved))).Alerts); Assert.Equal(first, resolved.Id);
        Assert.Equal([AlertEventKind.Opened, AlertEventKind.Acknowledged, AlertEventKind.Resolved], (await f.Alerts.ReadEventsAsync(first)).Select(e => e.Kind));
        await f.Alerts.ApplyAsync(Observe(f, ["Offline"])); var next = Assert.Single((await f.Alerts.ReadAsync(new(ActiveOnly: true))).Alerts);
        Assert.NotEqual(first, next.Id); Assert.Null(next.AcknowledgedUtc); Assert.Equal(2, (await f.Alerts.ReadAsync(new())).Alerts.Length);
    }
    [Fact]
    public async Task AlertsAndAcknowledgementsSurviveRestartAndOneWriterIsEnforced()
    {
        await using var f = await OperationsFixture.CreateAsync(); await f.Alerts.ApplyAsync(Observe(f, ["EventsLost"]));
        var first = Assert.Single((await f.Alerts.ReadAsync(new())).Alerts);
        await f.Alerts.AcknowledgeAsync(first.Id, "operator", f.Audits.Clock.GetUtcNow());
        await Assert.ThrowsAsync<IOException>(() => SqliteAlertStore.OpenAsync(new() { DatabasePath = f.DatabasePath }));
        await f.Alerts.DisposeAsync(); await using var reopened = await SqliteAlertStore.OpenAsync(new() { DatabasePath = f.DatabasePath });
        var retained = Assert.Single((await reopened.ReadAsync(new())).Alerts); Assert.Equal(AlertState.Acknowledged, retained.State);
        await reopened.ApplyAsync(Observe(f, ["EventsLost"])); Assert.Single((await reopened.ReadAsync(new())).Alerts);
        Assert.Equal(2, (await reopened.ReadEventsAsync(first.Id)).Length);
    }
    [Fact]
    public async Task ConcurrentDuplicateObservationsAndAcknowledgementsHaveOneTransitionEach()
    {
        await using var f = await OperationsFixture.CreateAsync();
        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => f.Alerts.ApplyAsync(Observe(f, ["CollectorFaulted"]))));
        var alert = Assert.Single((await f.Alerts.ReadAsync(new())).Alerts);
        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => f.Alerts.AcknowledgeAsync(alert.Id, "operator", f.Audits.Clock.GetUtcNow())));
        Assert.Equal(2, (await f.Alerts.ReadEventsAsync(alert.Id)).Length);
    }
    [Fact]
    public async Task QueriesPageAndScopeAlertsWithoutDuplicatingOrLeakingOtherNodes()
    {
        await using var f = await OperationsFixture.CreateAsync(); await f.Alerts.ApplyAsync(Observe(f, ["EventsLost", "Offline", "StaleHeartbeat"]));
        var otherLedger = Guid.NewGuid(); await f.Alerts.ApplyAsync(new("other", otherLedger, f.Audits.Clock.GetUtcNow(), [new("NoHeartbeat", AlertSeverity.Warning)], true));
        var first = await f.Alerts.ReadAsync(new(f.NodeId, f.LedgerId, Limit: 2)); Assert.Equal(2, first.Alerts.Length); Assert.NotNull(first.NextBeforeId);
        var last = await f.Alerts.ReadAsync(new(f.NodeId, f.LedgerId, BeforeId: first.NextBeforeId, Limit: 2)); Assert.Single(last.Alerts); Assert.Null(last.NextBeforeId);
        Assert.All(first.Alerts.Concat(last.Alerts), a => Assert.Equal(f.NodeId, a.NodeId));
        await Assert.ThrowsAsync<ArgumentException>(() => f.Alerts.ReadAsync(new(NodeId: f.NodeId)));
        await Assert.ThrowsAsync<ArgumentException>(() => f.Alerts.ReadAsync(new(Limit: 101)));
    }
    [Fact]
    public async Task CapacityFailureRollsBackAllConditionTransitionsAndCanceledWritesLeaveNoRows()
    {
        await using var f = await OperationsFixture.CreateAsync(); await f.Alerts.DisposeAsync();
        await using var store = await SqliteAlertStore.OpenAsync(new() { DatabasePath = f.DatabasePath, MaximumStoredAlerts = 1 });
        await store.ApplyAsync(Observe(f, ["Offline"]));
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.ApplyAsync(Observe(f, ["StaleHeartbeat"])));
        Assert.Equal("Offline", Assert.Single((await store.ReadAsync(new(ActiveOnly: true))).Alerts).Code);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.ApplyAsync(Observe(f, []), canceled.Token));
        Assert.Equal(1, (await store.CountAsync()).Open);
    }
    [Fact]
    public async Task ReceiverClockRollbackCannotResolveOrRewriteAnAlert()
    {
        await using var f = await OperationsFixture.CreateAsync(); await f.Alerts.ApplyAsync(Observe(f, ["Offline"]));
        f.Audits.Clock.Advance(TimeSpan.FromSeconds(-1));
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Alerts.ApplyAsync(Observe(f, [])));
        var alert = Assert.Single((await f.Alerts.ReadAsync(new())).Alerts); Assert.Null(alert.ResolvedUtc);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Alerts.AcknowledgeAsync(alert.Id, "operator", f.Audits.Clock.GetUtcNow()));
        Assert.Single(await f.Alerts.ReadEventsAsync(alert.Id));
    }
    [Fact]
    public async Task InvalidOrDuplicateConditionCodesCannotEnterOperationalHistory()
    {
        await using var f = await OperationsFixture.CreateAsync();
        await Assert.ThrowsAsync<ArgumentException>(() => f.Alerts.ApplyAsync(Observe(f, ["MadeUpCondition"])));
        await Assert.ThrowsAsync<ArgumentException>(() => f.Alerts.ApplyAsync(Observe(f, ["Offline", "Offline"])));
        await Assert.ThrowsAsync<ArgumentException>(() => f.Alerts.ApplyAsync(Observe(f, ["Offline"], false)));
        Assert.Empty((await f.Alerts.ReadAsync(new())).Alerts);
    }
}
