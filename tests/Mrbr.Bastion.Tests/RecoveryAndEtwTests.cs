using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Core;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class RecoveryAndEtwTests
{
    [Fact]
    public async Task ProcessDeathRecoversCommittedWalAndDiscardsUncommittedPages()
    {
        using var fixture = new TestLedger();
        Directory.CreateDirectory(fixture.DirectoryPath);
        var keyPath = Path.Combine(fixture.DirectoryPath, "test-key.pem");
        File.WriteAllText(keyPath, fixture.NodeKey.ExportPkcs8PrivateKeyPem());
        using var child = StartProbe(fixture.Options.DatabasePath, keyPath);
        try
        {
            string? ready = await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal("READY", ready);
        }
        finally
        {
            if (!child.HasExited) child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        }
        await using var cache = await TestLedger.AfterProcessExitAsync(()=>fixture.OpenAsync());
        var recovered = Assert.Single(await cache.ReadPendingAsync());
        Assert.Equal(1, recovered.Content.SequenceNumber);
        var next = await cache.AppendAsync([TestLedger.Event()]);
        Assert.Equal(2, next.Content.SequenceNumber);
        Assert.Equal(recovered.BlockHash, next.Content.PreviousBlockHash);
        await cache.VerifyIntegrityAsync();
    }

    [WindowsPrivilegeFact(elevated: false)]
    public async Task NonElevatedEtwFailsDescriptivelyAndFaultsTheMonitor()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var source = new WindowsEtwTelemetrySource();
        var monitor = new TelemetryMonitor(source, cache);
        var error = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => monitor.RunAsync());
        Assert.Contains("Administrator", error.Message);
        Assert.Equal(MonitorState.Faulted, monitor.GetHealth().State);
        Assert.Equal(0, monitor.GetHealth().PersistedEvents);
    }

    [WindowsPrivilegeFact(elevated: true)]
    public async Task LiveEtwCapturesChildProcessAndFileReadWriteAndStopsCleanly()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        using var stop = new CancellationTokenSource();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var sawRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var sawWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        string fileName = $"bastion-probe-{Guid.NewGuid():N}.txt";
        // Observe our own startup rundown so the child's parent lifetime is known before launch.
        // The filter below excludes our file activity, preventing cache-write feedback.
        var source = new WindowsEtwTelemetrySource(new() { ExcludeCollectorProcess = false });
        var monitor = new TelemetryMonitor(source, cache, new()
        {
            Filter = item =>
            {
                if (item.ProcessId == Environment.ProcessId && item.Kind == TelemetryEventKind.ProcessSnapshot)
                    ready.TrySetResult();
                bool probe = item.FilePath?.EndsWith(fileName, StringComparison.OrdinalIgnoreCase) == true;
                if (probe && item.Kind == TelemetryEventKind.FileRead) sawRead.TrySetResult();
                if (probe && item.Kind == TelemetryEventKind.FileWritten) sawWrite.TrySetResult();
                return probe || item.Kind is TelemetryEventKind.ProcessStarted or TelemetryEventKind.ProcessStopped;
            }
        });
        var run = monitor.RunAsync(stop.Token);
        int childPid;
        try
        {
            // Propagate setup errors promptly, rather than waiting for the readiness timeout.
            await Task.WhenAny(ready.Task, run).WaitAsync(TimeSpan.FromSeconds(10));
            if (run.IsCompleted) await run;
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var child = StartProbe("--io", Path.Combine(fixture.DirectoryPath, fileName));
            childPid = child.Id;
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(0, child.ExitCode);
            await Task.WhenAll(sawRead.Task, sawWrite.Task).WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            await stop.CancelAsync();
            await run.WaitAsync(TimeSpan.FromSeconds(10));
        }
        var events = (await cache.ReadPendingAsync()).SelectMany(LedgerProtocol.DeserializeEvents).ToArray();
        var childStart = Assert.Single(events, item => item.ProcessId == childPid && item.Kind == TelemetryEventKind.ProcessStarted);
        Assert.Equal(Environment.ProcessId, childStart.ParentProcessId);
        Assert.NotNull(childStart.ParentProcess);
        Assert.Equal(Environment.ProcessId, childStart.ParentProcess.ProcessId);
        Assert.Equal(childStart.ParentProcessInstanceId, childStart.ParentProcess.ProcessInstanceId);
        Assert.NotNull(childStart.ParentProcess.ExecutablePath);
        Assert.Contains(events, item => item.ProcessId == childPid && item.Kind == TelemetryEventKind.FileRead);
        Assert.Contains(events, item => item.ProcessId == childPid && item.Kind == TelemetryEventKind.FileWritten);
        Assert.Equal(MonitorState.Stopped, monitor.GetHealth().State);
        Assert.Equal(0, monitor.GetHealth().UnpersistedEvents);
    }

    [WindowsPrivilegeFact(elevated: true)]
    public async Task LiveEtwSourcesCaptureConcurrentlyAndStopIndependently()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TestLedger();
        Directory.CreateDirectory(fixture.DirectoryPath);
        string firstPath = Path.Combine(fixture.DirectoryPath, $"bastion-concurrent-first-{Guid.NewGuid():N}.txt");
        string secondPath = Path.Combine(fixture.DirectoryPath, $"bastion-concurrent-second-{Guid.NewGuid():N}.txt");
        using var fileStop = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        using var processStop = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var fileReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var processReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fileSawChild = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var processSawChild = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var processSawNextChild = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var sawWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fileSource = new WindowsEtwTelemetrySource(new() { ExcludeCollectorProcess = false });
        var processSource = new WindowsEtwTelemetrySource(new() { CollectFileEvents = false, ExcludeCollectorProcess = false });
        void Observe(TelemetryEvent item, TaskCompletionSource ready, TaskCompletionSource child)
        {
            if (item.ProcessId == Environment.ProcessId && item.Kind == TelemetryEventKind.ProcessSnapshot) ready.TrySetResult();
            if (item.Kind == TelemetryEventKind.ProcessStarted && item.CommandLine?.Contains(firstPath, StringComparison.OrdinalIgnoreCase) == true)
                child.TrySetResult();
        }
        var fileRun = fileSource.RunAsync(item =>
        {
            Observe(item, fileReady, fileSawChild);
            if (item.Kind == TelemetryEventKind.FileWritten && item.FilePath?.EndsWith(Path.GetFileName(firstPath), StringComparison.OrdinalIgnoreCase) == true)
                sawWrite.TrySetResult();
        }, fileStop.Token);
        var processRun = processSource.RunAsync(item =>
        {
            Observe(item, processReady, processSawChild);
            if (item.Kind == TelemetryEventKind.ProcessStarted && item.CommandLine?.Contains(secondPath, StringComparison.OrdinalIgnoreCase) == true)
                processSawNextChild.TrySetResult();
        }, processStop.Token);
        async Task AwaitObservation(Task observation)
        {
            await Task.WhenAny(observation, fileRun, processRun).WaitAsync(TimeSpan.FromSeconds(10));
            if (fileRun.IsCompleted && !fileStop.IsCancellationRequested) await fileRun;
            if (processRun.IsCompleted) await processRun;
            await observation.WaitAsync(TimeSpan.FromSeconds(10));
        }
        try
        {
            await AwaitObservation(Task.WhenAll(fileReady.Task, processReady.Task));
            using (var child = StartProbe("--io", firstPath))
            {
                await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                Assert.Equal(0, child.ExitCode);
            }
            await AwaitObservation(Task.WhenAll(fileSawChild.Task, processSawChild.Task, sawWrite.Task));
            await fileStop.CancelAsync();
            await fileRun.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.False(processRun.IsCompleted);
            using (var child = StartProbe("--io", secondPath))
            {
                await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                Assert.Equal(0, child.ExitCode);
            }
            await processSawNextChild.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.False(processRun.IsCompleted);
        }
        finally
        {
            await fileStop.CancelAsync(); await processStop.CancelAsync();
            await Task.WhenAll(fileRun, processRun).WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    internal static Process StartProbe(params string[] arguments)
    {
        var tests = typeof(RecoveryAndEtwTests).Assembly.Location;
        var info = new ProcessStartInfo("dotnet") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in new[] { "exec", "--runtimeconfig", Path.ChangeExtension(tests, "runtimeconfig.json"),
            "--depsfile", Path.ChangeExtension(tests, "deps.json"), typeof(CrashProbe.Program).Assembly.Location }.Concat(arguments))
            info.ArgumentList.Add(argument);
        return Process.Start(info) ?? throw new IOException("Cannot start the recovery test helper.");
    }
}

public sealed class WindowsPrivilegeFactAttribute : FactAttribute
{
    public WindowsPrivilegeFactAttribute(bool elevated)
    {
        if (!OperatingSystem.IsWindows()) Skip = "Requires Windows.";
        else if (IsElevated() != elevated) Skip = elevated ? "Requires an elevated Windows test host for live kernel ETW." : "Requires a non-elevated Windows test host.";
    }

    [SupportedOSPlatform("windows")]
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
