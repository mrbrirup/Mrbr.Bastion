using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Notifications;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class NotificationDispatcherTests
{
    [Fact]
    public async Task TransientFailureUsesDurableBackoffAndStableDeliveryIdentity()
    {
        await using var f = await NotificationFixture.CreateAsync();
        f.Transport.OnSend = (_, _) => Task.FromResult(f.Transport.Sent.Count == 1 ? NotificationResult.Retry("TemporaryFailure") : NotificationResult.Accepted());
        await f.ObserveAsync("Offline"); await f.Dispatcher.RunOnceAsync();
        var pending = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries); Assert.Equal(NotificationState.Pending, pending.State);
        Assert.Equal(f.Clock.GetUtcNow().AddSeconds(5), pending.NextAttemptUtc); await f.Dispatcher.RunOnceAsync(); Assert.Single(f.Transport.Sent);
        f.Clock.Advance(TimeSpan.FromSeconds(5)); await f.Dispatcher.RunOnceAsync(); Assert.Equal(2, f.Transport.Sent.Count);
        Assert.Equal(f.Transport.Sent[0].Body, f.Transport.Sent[1].Body); Assert.Equal(f.Transport.Sent[0].Message.DeliveryId, f.Transport.Sent[1].Message.DeliveryId);
        Assert.Equal(1, (await f.Queue.CountAsync()).Delivered);
    }
    [Fact]
    public async Task CapacityFailureStillAllowsAlreadyAdmittedWorkToDrain()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ReopenAsync(new() { DatabasePath = f.DatabasePath, MaximumStoredDeliveries = 1 });
        var dispatcher = new NotificationDispatcher(f.Operations.Alerts, f.Queue, [f.Transport], timeProvider: f.Clock); await dispatcher.InitializeAsync();
        await f.ObserveAsync("Offline"); await f.CopyAsync(); await f.ObserveAsync("Offline", "EventsLost");
        await dispatcher.RunOnceAsync(); Assert.NotNull(dispatcher.Status.RoutingError); Assert.Null(dispatcher.Status.DeliveryError);
        Assert.Equal(1, (await f.Queue.CountAsync()).Delivered); Assert.Equal(1, (await f.Queue.ReadSubscriptionAsync(f.Transport.Route.Id)).Cursor);
    }
    [Fact]
    public async Task ProviderAcceptanceIsCommittedEvenWhenShutdownStartsBeforeSendReturns()
    {
        await using var f = await NotificationFixture.CreateAsync(); using var shutdown = new CancellationTokenSource();
        f.Transport.OnSend = (_, _) => { shutdown.Cancel(); return Task.FromResult(NotificationResult.Accepted()); };
        await f.ObserveAsync("Offline");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Dispatcher.RunOnceAsync(shutdown.Token));
        Assert.Equal(1, (await f.Queue.CountAsync()).Delivered);
    }
    [Fact]
    public async Task CancellationDuringDeliveryLeavesALeaseForRecoveryRatherThanPretendingToFailOrSucceed()
    {
        await using var f = await NotificationFixture.CreateAsync(); using var shutdown = new CancellationTokenSource();
        f.Transport.OnSend = (_, token) => { shutdown.Cancel(); return Task.FromCanceled<NotificationResult>(token); };
        await f.ObserveAsync("Offline"); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Dispatcher.RunOnceAsync(shutdown.Token));
        var retained = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries); Assert.Equal(NotificationState.InFlight, retained.State);
        Assert.Equal(NotificationAttemptOutcome.Started, Assert.Single((await f.Queue.ReadDetailAsync(retained.Id))!.Attempts).Outcome);
    }
    [Fact]
    public async Task TimedOutAttemptsRetryAndProviderRetryAfterIsDurablyCapped()
    {
        await using var f = await NotificationFixture.CreateAsync(new() { AttemptTimeout = TimeSpan.FromMilliseconds(100), MaximumDeliveriesPerPass = 1 });
        f.Transport.OnSend = async (_, token) => { await Task.Delay(Timeout.Infinite, token); return NotificationResult.Accepted(); };
        await f.ObserveAsync("Offline"); await f.Dispatcher.RunOnceAsync();
        var pending = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries); Assert.Equal("AttemptTimedOut", pending.LastCode);
        f.Transport.OnSend = (_, _) => Task.FromResult(NotificationResult.Retry("Throttled", 429, TimeSpan.FromDays(100)));
        f.Clock.Advance(TimeSpan.FromSeconds(5)); await f.Dispatcher.RunOnceAsync();
        Assert.Equal(f.Clock.GetUtcNow().AddDays(1), Assert.Single((await f.Queue.ReadAsync(new())).Deliveries).NextAttemptUtc);
    }
    [Fact]
    public async Task UnknownTransportErrorsAndInvalidResultTextDoNotLeakCredentialsIntoHistory()
    {
        await using var f = await NotificationFixture.CreateAsync();
        f.Transport.OnSend = (_, _) => throw new IOException("password=not-a-real-secret");
        await f.ObserveAsync("Offline"); await f.Dispatcher.RunOnceAsync();
        Assert.Equal("TransportFailure", Assert.Single((await f.Queue.ReadAsync(new())).Deliveries).LastCode);
        f.Clock.Advance(TimeSpan.FromSeconds(5)); f.Transport.OnSend = (_, _) => Task.FromResult(NotificationResult.Retry("token=not-a-real-secret"));
        await f.Dispatcher.RunOnceAsync(); Assert.Equal("InvalidTransportOutcome", Assert.Single((await f.Queue.ReadAsync(new())).Deliveries).LastCode);
    }
    [Fact]
    public async Task DestinationsAreIsolatedAndSeverityFilteringDoesNotLoseCursorProgress()
    {
        await using var f = await NotificationFixture.CreateAsync(); var critical = new DelegateNotificationTransport("critical", minimum: AlertSeverity.Critical);
        var failing = new DelegateNotificationTransport("failing") { OnSend = (_, _) => Task.FromResult(NotificationResult.Permanent("DestinationRejected")) };
        var dispatcher = new NotificationDispatcher(f.Operations.Alerts, f.Queue, [critical, failing], timeProvider: f.Clock);
        await dispatcher.InitializeAsync(); await f.ObserveAsync("EventsLost"); await dispatcher.RunOnceAsync();
        Assert.Empty(critical.Sent); Assert.Single(failing.Sent); Assert.Equal(1, (await f.Queue.ReadSubscriptionAsync(critical.Route.Id)).Cursor);
        await f.ObserveAsync("EventsLost", "Offline"); await dispatcher.RunOnceAsync();
        Assert.Single(critical.Sent); Assert.Equal(1, (await f.Queue.CountAsync()).Delivered); Assert.Equal(2, (await f.Queue.CountAsync()).DeadLetter);
    }
}
