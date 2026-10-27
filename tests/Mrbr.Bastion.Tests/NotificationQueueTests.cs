using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Notifications;
using Mrbr.Bastion.Notifications.Sqlite;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class NotificationQueueTests
{
    [Fact]
    public async Task RouteCursorsAndImmutableDeliveryIdsSurviveRestartWithoutDuplicateEnqueueing()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline"); await f.CopyAsync();
        var original = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries);
        await f.ReopenAsync(); await f.CopyAsync();
        Assert.Equal(original, Assert.Single((await f.Queue.ReadAsync(new())).Deliveries));
        Assert.Equal(1, (await f.Queue.ReadSubscriptionAsync(f.Transport.Route.Id)).Cursor);
        await Assert.ThrowsAsync<IOException>(() => SqliteNotificationQueue.OpenAsync(new() { DatabasePath = f.DatabasePath }));
    }
    [Fact]
    public async Task NewRoutesSkipOldEventsByDefaultAndReplayRequiresAnExplicitSubscriptionChoice()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline");
        var normal = new DelegateNotificationTransport("new-route"); var replay = new DelegateNotificationTransport("replay-route", replay: true);
        var position = await f.Operations.Alerts.ReadPositionAsync();
        await f.Queue.RegisterAsync(normal.Route, position); await f.Queue.RegisterAsync(replay.Route, position);
        await f.CopyAsync(normal.Route); await f.CopyAsync(replay.Route);
        Assert.Empty((await f.Queue.ReadAsync(new(RouteId: normal.Route.Id))).Deliveries);
        Assert.Single((await f.Queue.ReadAsync(new(RouteId: replay.Route.Id))).Deliveries);
        await f.ObserveAsync(); await f.CopyAsync(normal.Route);
        Assert.Equal(AlertEventKind.Resolved, Assert.Single((await f.Queue.ReadAsync(new(RouteId: normal.Route.Id))).Deliveries).EventKind);
    }
    [Fact]
    public async Task DestinationOrFilterRebindingAndFeedReplacementRequireExplicitNewIdentities()
    {
        await using var f = await NotificationFixture.CreateAsync(); var position = await f.Operations.Alerts.ReadPositionAsync();
        await Assert.ThrowsAsync<NotificationConflictException>(() => f.Queue.RegisterAsync(f.Transport.Route with { Fingerprint = NotificationRoute.HashDestination("another recipient") }, position));
        await Assert.ThrowsAsync<NotificationConflictException>(() => f.Queue.RegisterAsync(f.Transport.Route with { MinimumSeverity = AlertSeverity.Critical }, position));
        await Assert.ThrowsAsync<NotificationConflictException>(() => f.Queue.RegisterAsync(new DelegateNotificationTransport("another").Route, position with { FeedId = Guid.NewGuid() }));
    }
    [Fact]
    public async Task AtomicEnqueueFailureDoesNotAdvanceTheSourceCursorOrRetainHalfABatch()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ReopenAsync(new() { DatabasePath = f.DatabasePath, MaximumStoredDeliveries = 1 });
        await f.ObserveAsync("Offline", "StaleHeartbeat");
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.CopyAsync());
        Assert.Empty((await f.Queue.ReadAsync(new())).Deliveries); Assert.Equal(0, (await f.Queue.ReadSubscriptionAsync(f.Transport.Route.Id)).Cursor);
    }
    [Fact]
    public async Task OnlyOneConcurrentLeaseCanOwnADelivery()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline"); await f.CopyAsync();
        var claims = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60))));
        Assert.Single(claims, l => l is not null); Assert.Equal(1, (await f.Queue.CountAsync()).InFlight);
    }
    [Fact]
    public async Task ExpiredLeasesRecoverAfterRestartWithTheSamePayloadAndRejectLateAcknowledgements()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline"); await f.CopyAsync();
        var first = (await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)))!;
        await f.ReopenAsync(); Assert.Null(await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)));
        f.Clock.Advance(TimeSpan.FromSeconds(61)); var recovered = (await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)))!;
        Assert.Equal(first.Delivery.Id, recovered.Delivery.Id); Assert.Equal(first.Body, recovered.Body); Assert.NotEqual(first.Token, recovered.Token);
        await Assert.ThrowsAsync<NotificationConflictException>(() => f.Queue.CompleteAsync(first, NotificationResult.Accepted(), f.Clock.GetUtcNow(), f.Clock.GetUtcNow()));
        await f.Queue.CompleteAsync(recovered, NotificationResult.Accepted(), f.Clock.GetUtcNow(), f.Clock.GetUtcNow());
        var detail = (await f.Queue.ReadDetailAsync(first.Delivery.Id))!;
        Assert.Equal(NotificationAttemptOutcome.LeaseExpired, detail.Attempts[0].Outcome); Assert.Equal(NotificationAttemptOutcome.Accepted, detail.Attempts[1].Outcome);
        Assert.Equal(NotificationState.Delivered, detail.Delivery.State);
    }
    [Fact]
    public async Task RetryBudgetDeadLettersAndManualRetryPreservesPayloadAndAuditHistory()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline"); await f.CopyAsync(maximumAttempts: 2);
        var first = (await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)))!;
        await f.Queue.CompleteAsync(first, NotificationResult.Retry("TemporaryFailure"), f.Clock.GetUtcNow(), f.Clock.GetUtcNow().AddSeconds(5));
        Assert.Null(await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)));
        f.Clock.Advance(TimeSpan.FromSeconds(5)); var second = (await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)))!;
        await f.Queue.CompleteAsync(second, NotificationResult.Retry("TemporaryFailure"), f.Clock.GetUtcNow(), f.Clock.GetUtcNow().AddSeconds(5));
        Assert.Equal(1, (await f.Queue.CountAsync()).DeadLetter);
        var redriven = await f.Queue.RedriveAsync(first.Delivery.Id, "operator", f.Clock.GetUtcNow()); Assert.Equal(0, redriven!.CycleAttempts); Assert.Equal(2, redriven.Attempts);
        Assert.Equal(redriven, await f.Queue.RedriveAsync(first.Delivery.Id, "other", f.Clock.GetUtcNow()));
        var third = (await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)))!;
        Assert.Equal(first.Body, third.Body); await f.Queue.CompleteAsync(third, NotificationResult.Accepted(), f.Clock.GetUtcNow(), f.Clock.GetUtcNow());
        var detail = (await f.Queue.ReadDetailAsync(third.Delivery.Id))!; Assert.Equal(3, detail.Attempts.Length); Assert.Single(detail.Redrives); Assert.Equal("operator", detail.Redrives[0].Actor);
        Assert.Equal(NotificationState.Delivered, detail.Delivery.State);
    }
    [Fact]
    public async Task RepeatedCrashesCannotBypassTheAutomaticAttemptBudget()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline"); await f.CopyAsync(maximumAttempts: 1);
        _ = await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(5)); f.Clock.Advance(TimeSpan.FromSeconds(6));
        Assert.Null(await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(5)));
        Assert.Equal(1, (await f.Queue.CountAsync()).DeadLetter);
    }
    [Fact]
    public async Task OpenRetryBlocksItsResolutionWithoutBlockingUnrelatedAlerts()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline"); await f.ObserveAsync(); await f.ObserveAsync("EventsLost"); await f.CopyAsync();
        var opened = (await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)))!;
        await f.Queue.CompleteAsync(opened, NotificationResult.Retry("TemporaryFailure"), f.Clock.GetUtcNow(), f.Clock.GetUtcNow().AddSeconds(30));
        var unrelated = (await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)))!;
        Assert.NotEqual(opened.Delivery.AlertId, unrelated.Delivery.AlertId); Assert.Equal(AlertEventKind.Opened, unrelated.Delivery.EventKind);
        await f.Queue.CompleteAsync(unrelated, NotificationResult.Accepted(), f.Clock.GetUtcNow(), f.Clock.GetUtcNow());
        Assert.Null(await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)));
    }
    [Fact]
    public async Task InactiveRoutesRetainPendingWorkAndFilteredAcknowledgementsStillAdvanceTheCursor()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline");
        var alert = Assert.Single((await f.Operations.Alerts.ReadAsync(new())).Alerts);
        await f.Operations.Alerts.AcknowledgeAsync(alert.Id, "operator", f.Clock.GetUtcNow()); await f.ObserveAsync(); await f.CopyAsync();
        Assert.Equal(3, (await f.Queue.ReadSubscriptionAsync(f.Transport.Route.Id)).Cursor);
        Assert.Equal(2, (await f.Queue.CountAsync()).Pending);
        Assert.Null(await f.Queue.LeaseAsync([], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)));
        Assert.Equal(2, (await f.Queue.CountAsync()).Pending);
    }
    [Fact]
    public async Task CancellationAndClockRollbackLeaveQueuedWorkUnmodified()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline");
        using var stop = new CancellationTokenSource(); stop.Cancel();
        var position = await f.Queue.ReadSubscriptionAsync(f.Transport.Route.Id); var page = await f.Operations.Alerts.ReadChangesAsync(position.Cursor);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Queue.AppendAsync(f.Transport.Route, position.Cursor, page, f.Clock.GetUtcNow(), 8, stop.Token));
        Assert.Equal(0, (await f.Queue.ReadSubscriptionAsync(f.Transport.Route.Id)).Cursor); await f.CopyAsync();
        f.Clock.Advance(TimeSpan.FromSeconds(-1));
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)));
        Assert.Equal(1, (await f.Queue.CountAsync()).Pending);
    }
    [Fact]
    public async Task CorruptPayloadCannotBeLeasedAndSafeQueriesRemainBounded()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline"); await f.CopyAsync();
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.DatabasePath, Pooling = false }.ToString()); db.Open();
        using var edit = db.CreateCommand(); edit.CommandText = "UPDATE deliveries SET body=zeroblob(length(body))"; edit.ExecuteNonQuery();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)));
        Assert.Equal(1, (await f.Queue.CountAsync()).Pending); Assert.Equal(0, Assert.Single((await f.Queue.ReadAsync(new())).Deliveries).Attempts);
        await Assert.ThrowsAsync<ArgumentException>(() => f.Queue.ReadAsync(new(Limit: 101)));
    }
    [Fact]
    public async Task AbruptProcessTerminationRetainsCommittedLeaseAndRollsBackUncommittedPayloadEdits()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline"); await f.CopyAsync();
        var original = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries); await f.Queue.DisposeAsync();
        using var child = RecoveryAndEtwTests.StartProbe("--notifications", f.DatabasePath, f.Clock.GetUtcNow().UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var errors = child.StandardError.ReadToEndAsync();
        try { Assert.Equal("READY", await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15))); }
        finally { if (!child.HasExited) child.Kill(entireProcessTree: true); await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
        Assert.Equal("", await errors); await f.ReopenAsync();
        var retained = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries); Assert.Equal(original.Id, retained.Id); Assert.Equal(NotificationState.InFlight, retained.State);
        Assert.Null(retained.LastCode); f.Clock.Advance(TimeSpan.FromSeconds(61));
        var retry = (await f.Queue.LeaseAsync([f.Transport.Route.Id], f.Clock.GetUtcNow(), TimeSpan.FromSeconds(60)))!;
        Assert.Equal(original.Id, NotificationJson.Decode(retry.Body).DeliveryId);
        Assert.Equal(NotificationAttemptOutcome.LeaseExpired, (await f.Queue.ReadDetailAsync(original.Id))!.Attempts[0].Outcome);
        await f.Queue.CompleteAsync(retry, NotificationResult.Accepted(), f.Clock.GetUtcNow(), f.Clock.GetUtcNow());
        Assert.Equal(1, (await f.Queue.CountAsync()).Delivered);
    }
}
