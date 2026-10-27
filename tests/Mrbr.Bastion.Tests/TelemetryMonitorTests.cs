using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Core;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class TelemetryMonitorTests
{
    [Fact]
    public async Task SourceCompletionDrainsFinalPartialBatchToDurableStorage()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var source = new DelegateSource((emit, _) =>
        {
            for (int i = 0; i < 7; i++) emit(TestLedger.Event(i));
            return Task.CompletedTask;
        }, eventsLost: 3);
        var monitor = new TelemetryMonitor(source, cache, new() { BatchSize = 3 });
        await monitor.RunAsync();
        var health = monitor.GetHealth();
        Assert.Equal(MonitorState.Stopped, health.State);
        Assert.Equal(7, health.PersistedEvents);
        Assert.Equal(3, health.PersistedBlocks);
        Assert.Equal(3, health.SourceLostEvents);
        Assert.Equal(0, health.UnpersistedEvents);
        Assert.Equal(7, (await cache.ReadPendingAsync()).Sum(b => b.Content.EventCount));
    }

    [Fact]
    public async Task QueueOverflowIsCountedSeparatelyFromSourceLoss()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocking = new BlockingCache(cache, release.Task);
        var source = new DelegateSource(async (emit, _) =>
        {
            emit(TestLedger.Event());
            await blocking.Entered.Task;
            for (int i = 0; i < 10; i++) emit(TestLedger.Event());
            release.SetResult();
        }, eventsLost: 5);
        var monitor = new TelemetryMonitor(source, blocking, new() { BatchSize = 1, QueueCapacity = 1 });
        await monitor.RunAsync();
        var health = monitor.GetHealth();
        Assert.Equal(11, health.ReceivedEvents);
        Assert.Equal(9, health.QueueDroppedEvents);
        Assert.Equal(5, health.SourceLostEvents);
        Assert.Equal(2, health.PersistedEvents);
        Assert.Equal(0, health.UnpersistedEvents);
    }

    [Fact]
    public async Task CancellationStopsSourceThenCommitsAcceptedEvents()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        using var cancellation = new CancellationTokenSource();
        var emitted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new DelegateSource(async (emit, token) =>
        {
            emit(TestLedger.Event());
            emitted.SetResult();
            await Task.Delay(Timeout.Infinite, token);
        });
        var monitor = new TelemetryMonitor(source, cache);
        var run = monitor.RunAsync(cancellation.Token);
        await emitted.Task;
        await cancellation.CancelAsync();
        await run.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(MonitorState.Stopped, monitor.GetHealth().State);
        Assert.Single(await cache.ReadPendingAsync());
    }

    [Fact]
    public async Task IdlePartialBatchFlushesWithoutWaitingForAnotherEvent()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        using var cancellation = new CancellationTokenSource();
        var committed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var observing = new BlockingCache(cache, Task.CompletedTask, committed);
        var source = new DelegateSource(async (emit, token) =>
        {
            emit(TestLedger.Event());
            await Task.Delay(Timeout.Infinite, token);
        });
        var monitor = new TelemetryMonitor(source, observing, new() { FlushInterval = TimeSpan.FromMilliseconds(30) });
        var run = monitor.RunAsync(cancellation.Token);
        try { await committed.Task.WaitAsync(TimeSpan.FromSeconds(5)); }
        finally { await cancellation.CancelAsync(); await run; }
        Assert.Single(await cache.ReadPendingAsync());
    }

    [Fact]
    public async Task PersistenceFailureStopsTheSourceAndReportsUnpersistedEvidence()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var blocking = new BlockingCache(cache, Task.FromException(new IOException("disk full")));
        var sourceStopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new DelegateSource(async (emit, token) =>
        {
            try
            {
                emit(TestLedger.Event());
                await Task.Delay(Timeout.Infinite, token);
            }
            finally { sourceStopped.SetResult(); }
        });
        var monitor = new TelemetryMonitor(source, blocking, new() { BatchSize = 1 });
        await Assert.ThrowsAsync<IOException>(() => monitor.RunAsync().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(sourceStopped.Task.IsCompleted);
        var health = monitor.GetHealth();
        Assert.Equal(MonitorState.Faulted, health.State);
        Assert.Equal(1, health.UnpersistedEvents);
        Assert.Equal(0, health.PersistedEvents);
        Assert.Contains("disk full", health.LastError);
    }

    [Fact]
    public async Task FaultingCancellationCallbackDoesNotPreventSourceAndConsumerCleanup()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var failing = new BlockingCache(cache, Task.FromException(new IOException("disk full")));
        var sourceStopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackFired = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new DelegateSource(async (emit, token) =>
        {
            using var registration = token.Register(() =>
            { callbackFired.TrySetResult(); throw new InvalidOperationException("stop callback failed"); });
            try
            {
                emit(TestLedger.Event());
                await Task.Delay(Timeout.Infinite, token);
            }
            finally
            {
                // CancelAsync can resume Delay before this earlier callback runs. Keep its registration alive
                // so the test exercises an actual callback failure rather than racing its disposal.
                await callbackFired.Task.WaitAsync(TimeSpan.FromSeconds(5));
                sourceStopped.SetResult();
            }
        });
        var monitor = new TelemetryMonitor(source, failing, new() { BatchSize = 1 });
        var error = await Assert.ThrowsAsync<AggregateException>(() => monitor.RunAsync().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Contains("disk full", error.ToString());
        Assert.Contains("stop callback failed", error.ToString());
        Assert.True(sourceStopped.Task.IsCompleted);
        Assert.Equal(MonitorState.Faulted, monitor.GetHealth().State);
    }

    [Fact]
    public async Task SourceFailureStillDrainsAcceptedEventsBeforeFaulting()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var source = new DelegateSource((emit, _) =>
        {
            emit(TestLedger.Event());
            throw new IOException("ETW stopped");
        });
        var monitor = new TelemetryMonitor(source, cache);
        await Assert.ThrowsAsync<IOException>(() => monitor.RunAsync());
        Assert.Equal(MonitorState.Faulted, monitor.GetHealth().State);
        Assert.Equal(1, monitor.GetHealth().PersistedEvents);
        Assert.Single(await cache.ReadPendingAsync());
    }

    [Fact]
    public async Task FiltersAreCountedAndMonitorCannotRunTwice()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var source = new DelegateSource((emit, _) =>
        {
            emit(TestLedger.Event(1));
            emit(TestLedger.Event(2));
            return Task.CompletedTask;
        });
        var monitor = new TelemetryMonitor(source, cache, new() { Filter = item => item.ProcessId == 2 });
        await monitor.RunAsync();
        Assert.Equal(1, monitor.GetHealth().FilteredEvents);
        Assert.Equal(1, monitor.GetHealth().PersistedEvents);
        await Assert.ThrowsAsync<InvalidOperationException>(() => monitor.RunAsync());
    }

    private sealed class BlockingCache(ITelemetryCache inner, Task release,
        TaskCompletionSource? committed = null) : ITelemetryCache
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<SignedTelemetryBlock> AppendAsync(IReadOnlyList<TelemetryEvent> events, CancellationToken cancellationToken = default)
        {
            Entered.TrySetResult();
            await release;
            var block = await inner.AppendAsync(events, cancellationToken);
            committed?.TrySetResult();
            return block;
        }
        public Task<IReadOnlyList<SignedTelemetryBlock>> ReadPendingAsync(int maximumBlocks = 100, CancellationToken cancellationToken = default) => inner.ReadPendingAsync(maximumBlocks, cancellationToken);
        public Task ReconcileAsync(SettlementReceipt receipt, CancellationToken cancellationToken = default) => inner.ReconcileAsync(receipt, cancellationToken);
        public Task VerifyIntegrityAsync(LedgerCheckpoint? trustedCheckpoint = null, CancellationToken cancellationToken = default) => inner.VerifyIntegrityAsync(trustedCheckpoint, cancellationToken);
        public Task<CacheStatus> GetStatusAsync(CancellationToken cancellationToken = default) => inner.GetStatusAsync(cancellationToken);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
