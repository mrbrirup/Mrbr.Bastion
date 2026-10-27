using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Mrbr.Bastion.Core;
using Mrbr.Bastion.Hosting;

namespace Mrbr.Bastion.Configuration;

public sealed record RunPlan(string Executable, string[] Arguments, string WorkingDirectory, Dictionary<string, string> Environment)
{
    public static RunPlan Create(LauncherProfile p, RunTarget target)
    {
        string project = target switch { RunTarget.Receiver => "Mrbr.Bastion.Server", RunTarget.Collector => "Mrbr.Bastion.Console", _ => "Mrbr.Bastion.Inventory.Agent" };
        string file = target switch { RunTarget.Receiver => p.Runtime.ReceiverExecutable, RunTarget.Collector => p.Runtime.CollectorExecutable, _ => p.Runtime.InventoryExecutable };
        if (string.IsNullOrWhiteSpace(file))
        {
            string folder = target == RunTarget.Collector ? Path.Combine("samples", project) : project;
            file = Path.Combine(p.Runtime.SolutionDirectory, folder, "bin", p.Runtime.BuildConfiguration.ToString(), "net11.0", project + ".dll");
        }
        file = Path.GetFullPath(file);
        if (!File.Exists(file)) throw new FileNotFoundException("Build the solution or select a published executable: " + file);
        var arguments = new List<string>();
        bool dll = Path.GetExtension(file).Equals(".dll", StringComparison.OrdinalIgnoreCase);
        if (dll) arguments.Add(file);
        if (target == RunTarget.Receiver) arguments.AddRange(["--config", p.ReceiverFile]);
        else if (target == RunTarget.Inventory) arguments.Add(p.InventoryFile);
        else
        {
            var c = p.Collector;
            arguments.AddRange([c.NodeId, p.Resolve(c.CacheDatabasePath), p.Resolve(c.NodePrivateKeyPath), p.Resolve(c.ReceiverPublicKeyPath), c.Transport, c.ServiceUri]);
            if (c.SendOnly) arguments.Add("--send-only");
            if (!c.Audits) arguments.Add("--no-audits");
            if (!c.ExcludeManagedProcessFileIo) arguments.Add("--include-managed-file-io");
            arguments.AddRange(["--cache-capacity-bytes", c.MaximumStoredPayloadBytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "--retention-config", p.RetentionFile]);
            arguments.AddRange(["--queue-capacity", c.QueueCapacity.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--batch-size", c.BatchSize.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--flush-ms", c.FlushIntervalMilliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--etw-buffer-mb", c.EtwBufferSizeMegabytes.ToString(System.Globalization.CultureInfo.InvariantCulture)]);
        }
        return new(dll ? p.Runtime.DotnetExecutable : file, arguments.ToArray(), Path.GetFullPath(p.DeploymentDirectory),
            target == RunTarget.Receiver ? ProfileStorage.ReceiverSecrets(p.Receiver) : new());
    }
}

public sealed class ManagedProcesses
{
    private sealed record Child(Process Process, string Pipe, string Token, Task Output, Task Error)
    { public TaskCompletionSource Exited { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously); }
    private readonly Dictionary<RunTarget, Child> _children = [];
    private readonly object _gate = new();
    public event Action<string>? Output;
    public event Action? Changed;
    public bool AnyRunning { get { lock (_gate) return _children.Count > 0; } }
    public string Status(RunTarget target)
    { lock (_gate) return _children.TryGetValue(target, out var child) ? $"Running · PID {child.Process.Id}" : "Stopped"; }

    public void Start(RunTarget target, RunPlan plan)
    {
        lock (_gate)
        {
            if (_children.ContainsKey(target)) throw new InvalidOperationException(target + " is already running.");
            string pipe = "bastion-" + Guid.NewGuid().ToString("N"), token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var info = new ProcessStartInfo(plan.Executable) { UseShellExecute = false, CreateNoWindow = true,
                WorkingDirectory = plan.WorkingDirectory, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string argument in plan.Arguments) info.ArgumentList.Add(argument);
            foreach (var value in plan.Environment) info.Environment[value.Key] = value.Value;
            info.Environment[LocalProcessControl.PipeVariable] = pipe;
            info.Environment[LocalProcessControl.TokenVariable] = token;
            info.Environment[LocalProcessControl.FileIoProcessesVariable] = FileIoPolicy();
            var process = Process.Start(info) ?? throw new IOException("The process could not be started.");
            string[] secrets = plan.Environment.Values.Where(v => !string.IsNullOrEmpty(v)).OrderByDescending(v => v.Length).ToArray();
            async Task Read(StreamReader reader)
            {
                while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
                {
                    foreach (string secret in secrets) line = line.Replace(secret, "[redacted]", StringComparison.Ordinal);
                    Output?.Invoke($"[{target}] {line}");
                }
            }
            var child = new Child(process, pipe, token, Read(process.StandardOutput), Read(process.StandardError));
            _children.Add(target, child);
            _ = ObserveAsync(target, child);
        }
        Changed?.Invoke();
    }
    public async Task StartAsync(RunTarget target, RunPlan plan)
    {
        Start(target, plan);
        if (target == RunTarget.Collector) return; // Its initial environment already contains the current scope.
        Child? collector; string policy;
        lock (_gate) { _children.TryGetValue(RunTarget.Collector, out collector); policy = FileIoPolicy(); }
        if (collector is null) return;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try { await LocalProcessControl.UpdateFileIoAsync(collector.Pipe, collector.Token, policy, timeout.Token).ConfigureAwait(false); }
        catch (Exception error) when (error is IOException or OperationCanceledException)
        { throw new IOException("The new process started, but collector file-I/O exclusions could not be refreshed. Stop collection before continuing the local run.", error); }
    }
    // Called while holding _gate. Only processes started by this panel and the panel itself are included.
    private string FileIoPolicy()
    {
        using var panel = Process.GetCurrentProcess();
        var identities = new List<FileIoProcessIdentity> { FileIoProcessIdentity.Capture(panel) };
        foreach (var child in _children.Values)
        {
            try { if (!child.Process.HasExited) identities.Add(FileIoProcessIdentity.Capture(child.Process)); }
            catch (InvalidOperationException) { }
        }
        return JsonSerializer.Serialize(identities);
    }
    private async Task ObserveAsync(RunTarget target, Child child)
    {
        try
        {
            await child.Process.WaitForExitAsync().ConfigureAwait(false);
            await Task.WhenAll(child.Output, child.Error).ConfigureAwait(false);
            Output?.Invoke($"[{target}] Exited with code {child.Process.ExitCode}.");
        }
        catch (Exception error) { Output?.Invoke($"[{target}] Output capture ended: {error.GetType().Name}."); }
        finally
        {
            lock (_gate) { _children.Remove(target); child.Process.Dispose(); }
            child.Exited.TrySetResult();
            Changed?.Invoke();
        }
    }
    public async Task StopAsync(RunTarget target)
    {
        Child? child;
        lock (_gate) _children.TryGetValue(target, out child);
        if (child is null) return;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await LocalProcessControl.RequestStopAsync(child.Pipe, child.Token, timeout.Token).ConfigureAwait(false);
            await child.Exited.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (ObjectDisposedException) { }
        catch (IOException) when (child.Exited.Task.IsCompleted) { }
        catch (OperationCanceledException) { throw new TimeoutException(target + " did not stop in 30 seconds. Inspect its log; Force stop is available separately."); }
    }
    public async Task StopAllAsync()
    { foreach (var target in new[] { RunTarget.Inventory, RunTarget.Collector, RunTarget.Receiver }) await StopAsync(target).ConfigureAwait(false); }
    public void ForceStop(RunTarget target)
    {
        lock (_gate)
            if (_children.TryGetValue(target, out var child) && !child.Process.HasExited) child.Process.Kill(entireProcessTree: true);
    }
}
