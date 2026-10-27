using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Core;
using Mrbr.Bastion.Console;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class ProcessFileIoFilterTests
{
    [Fact]
    public void SourceIdsAreUniqueAndRestoredPayloadsNeverInventIdentities()
    {
        var sequence = new EventIdSequence(Guid.NewGuid());
        var ids = Enumerable.Range(0, 10000).Select(_ => sequence.Next()).ToArray();
        Assert.DoesNotContain(Guid.Empty, ids); Assert.Equal(ids.Length, ids.Distinct().Count());
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var original = TestLedger.Event() with { EventId = ids[0] };
        string json = JsonSerializer.Serialize(original, options);
        Assert.Equal(ids[0], JsonSerializer.Deserialize<TelemetryEvent>(json, options)!.EventId);
        var missing = JsonNode.Parse(json)!.AsObject(); missing.Remove("eventId");
        try { Assert.Equal(Guid.Empty, JsonSerializer.Deserialize<TelemetryEvent>(missing.ToJsonString(), options)!.EventId); }
        catch (JsonException) { } // A strict constructor-parameter policy can reject the missing ID immediately.
    }

    [Fact]
    public void OnlySystemsExactOwnTransportArtifactIsSuppressed()
    {
        const string path = @"C:\Windows\System32\LogFiles\WMI\RtBackup\EtwRTMrbr.Bastion.test.etl";
        var filter = new RealtimeTraceLogFilter(@"C:\Windows", "Mrbr.Bastion.test");
        Assert.False(filter.Retain(4, path)); Assert.False(filter.Retain(4, path.ToUpperInvariant()));
        Assert.False(filter.Retain(4, @"\??\" + path));
        Assert.True(filter.Retain(123, path)); Assert.True(filter.Retain(4, null));
        Assert.True(filter.Retain(4, @"C:\other\EtwRTMrbr.Bastion.test.etl"));
        Assert.True(filter.Retain(4, path.Replace(".test.", ".other.")));
        int copies = 0;
        var dispatcher = new FilteredFileEventDispatcher(_ => true, filter.Retain);
        var callback = dispatcher.CreateCallback((int pid) => pid, pid => { copies++; return TestLedger.Event(pid); }, _ => { }, _ => path);
        callback(4); callback(123);
        Assert.Equal(1, copies); Assert.Equal(1, dispatcher.FilteredEvents);
    }

    [Fact]
    public void ExcludedRawIoNeverRunsTheEventFactory()
    {
        int copied = 0, published = 0;
        var dispatcher = new FilteredFileEventDispatcher(pid => pid != 42);
        var callback = dispatcher.CreateCallback((int pid) => pid, pid =>
        { copied++; return TestLedger.Event(pid); }, _ => published++);
        for (int i = 0; i < 10000; i++) callback(42);
        Assert.Equal(0, copied); Assert.Equal(0, published);
        Assert.Equal(10000, dispatcher.FilteredEvents);
        callback(43);
        Assert.Equal(1, copied); Assert.Equal(1, published);
    }

    [Fact]
    public async Task RawSourceExclusionsAreCountedWithoutBecomingLossOrBacklog()
    {
        using var fixture = new TestLedger(); await using var cache = await fixture.OpenAsync();
        var monitor = new TelemetryMonitor(new PrefilteredSource(), cache);
        await monitor.RunAsync(); var health = monitor.GetHealth();
        Assert.Equal(10001, health.ReceivedEvents); Assert.Equal(10000, health.FilteredEvents);
        Assert.Equal(1, health.PersistedEvents); Assert.Equal(0, health.QueueDroppedEvents);
        Assert.Equal(5, health.SourceLostEvents); Assert.Equal(0, health.UnpersistedEvents);
    }

    private sealed class PrefilteredSource : IFilteredTelemetrySource
    {
        public long FilteredEvents => 10000;
        public long EventsLost => 5;
        public Task RunAsync(Action<TelemetryEvent> onEvent, CancellationToken cancellationToken = default)
        { onEvent(TestLedger.Event()); return Task.CompletedTask; }
    }

    [Fact]
    public void ExclusionsAreBoundToLifetimesAndRetainLifecycleDescendantsAndOtherActors()
    {
        using var process = Process.GetCurrentProcess();
        var identity = FileIoProcessIdentity.Capture(process);
        using var filter = new ProcessFileIoFilter(int.MaxValue);
        filter.Update([identity]);
        var file = TestLedger.Event(process.Id) with { Kind = TelemetryEventKind.FileWritten, FilePath = "C:/Bastion/data/central.db" };
        Assert.False(filter.Retain(file));
        foreach (var kind in new[] { TelemetryEventKind.ProcessStarted, TelemetryEventKind.ProcessStopped, TelemetryEventKind.ProcessSnapshot })
            Assert.True(filter.Retain(file with { Kind = kind }));
        // A child/other process accessing the same protected file remains evidence.
        Assert.True(filter.Retain(file with { ProcessId = int.MaxValue - 1, ParentProcessId = process.Id }));
        filter.Update([identity with { StartedUtcTicks = identity.StartedUtcTicks + 1 }]);
        Assert.True(filter.Retain(file));
        filter.Update([identity]);
        Assert.Throws<ArgumentException>(() => filter.Update([identity, identity]));
        Assert.False(filter.Retain(file)); // A rejected update does not discard the active policy.
        filter.Update([]);
        Assert.True(filter.Retain(file));
    }

    [Fact]
    public async Task ExitedProcessExclusionsDoNotHideLaterUseOfItsPid()
    {
        using var child = RecoveryAndEtwTests.StartProbe("--desktop-control");
        try
        {
            Assert.Equal("CONTROL READY", await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15)));
            using var filter = new ProcessFileIoFilter(int.MaxValue);
            filter.Update([FileIoProcessIdentity.Capture(child)]);
            var file = TestLedger.Event(child.Id) with { Kind = TelemetryEventKind.FileRead };
            Assert.False(filter.Retain(file));
            child.Kill(entireProcessTree: true); await child.WaitForExitAsync();
            Assert.True(filter.Retain(file));
        }
        finally { if (!child.HasExited) { child.Kill(entireProcessTree: true); await child.WaitForExitAsync(); } }
    }

    [Fact]
    public async Task FeedbackBurstIsFilteredBeforeBoundedQueueAndRealEvidenceIsPersisted()
    {
        using var fixture = new TestLedger(); await using var cache = await fixture.OpenAsync();
        using var managed = Process.GetCurrentProcess();
        using var filter = new ProcessFileIoFilter(int.MaxValue);
        filter.Update([FileIoProcessIdentity.Capture(managed)]);
        var noise = TestLedger.Event(managed.Id) with { Kind = TelemetryEventKind.FileWritten };
        var actual = TestLedger.Event(int.MaxValue - 1) with { Kind = TelemetryEventKind.ProcessStarted, ParentProcessId = managed.Id };
        var source = new DelegateSource((emit, _) =>
        {
            for (int i = 0; i < 10000; i++) emit(noise);
            emit(actual); return Task.CompletedTask;
        });
        var monitor = new TelemetryMonitor(source, cache, new() { QueueCapacity = 1, Filter = filter.Retain });
        await monitor.RunAsync();
        var health = monitor.GetHealth();
        Assert.Equal(10001, health.ReceivedEvents); Assert.Equal(10000, health.FilteredEvents);
        Assert.Equal(0, health.QueueDroppedEvents); Assert.Equal(0, health.SourceLostEvents);
        Assert.Equal(1, health.PersistedEvents); Assert.Equal(0, health.UnpersistedEvents);
        Assert.Equal(actual.EventId, Assert.Single((await cache.ReadPendingAsync()).SelectMany(LedgerProtocol.DeserializeEvents)).EventId);
    }

    [Fact]
    public void CollectorOptionsPreserveExplicitTuningAndFilteringChoice()
    {
        var parsed = CollectorCommandLine.Parse(["node", "cache.db", "private.pem", "public.pem", "http", "https://localhost:7447",
            "--include-managed-file-io", "--exclude-file-process", "123", "--queue-capacity", "32768", "--batch-size", "250", "--flush-ms", "500", "--etw-buffer-mb", "128"]);
        Assert.False(parsed.ExcludeManagedFileIo); Assert.Equal([123], parsed.AdditionalFileIoProcessIds);
        Assert.Equal(32768, parsed.Monitor.QueueCapacity); Assert.Equal(250, parsed.Monitor.BatchSize);
        Assert.Equal(TimeSpan.FromMilliseconds(500), parsed.Monitor.FlushInterval); Assert.Equal(128, parsed.EtwBufferMegabytes);
    }

    [Theory]
    [InlineData("--queue-capacity", "0")]
    [InlineData("--queue-capacity", "1000001")]
    [InlineData("--batch-size", "10001")]
    [InlineData("--batch-size", "1001")]
    [InlineData("--flush-ms", "0")]
    [InlineData("--etw-buffer-mb", "1025")]
    [InlineData("--exclude-file-process", "0")]
    [InlineData("--unknown-option", "1")]
    public void InvalidCollectorOptionsFailBeforeStartingCollection(string option, string value) =>
        Assert.ThrowsAny<ArgumentException>(() => CollectorCommandLine.Parse(["node", "cache.db", "private.pem", "public.pem", option, value]));
}
