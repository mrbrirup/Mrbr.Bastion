using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using Mrbr.Bastion.Console;
using Mrbr.Bastion.Hosting;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Core;
using Mrbr.Bastion.Transport;
using Mrbr.Bastion.Transport.Http;
using Mrbr.Bastion.Transport.Grpc;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Auditing.Agent;

if (args.Length == 1 && args[0] == "--help")
{
    Console.WriteLine("Usage: Mrbr.Bastion.Console <node-id> <cache.db> <node-private.pem> <receiver-public.pem> [http|grpc <https-service-uri>] [--send-only|--inspect|--health|--retain|--compact] [--retention-config <json-file>] [--cache-capacity-mb <MB>|--cache-capacity-bytes <bytes>] [--no-audits] [--include-managed-file-io] [--exclude-file-process <PID>] [--queue-capacity <events>] [--batch-size <events>] [--flush-ms <milliseconds>] [--etw-buffer-mb <MB>]");
    Console.WriteLine("--inspect prints the ledger identity for enrollment. --send-only delivers an existing outbox without ETW or elevation.");
    Console.WriteLine("Live collection requires Windows and Administrator privileges. Ctrl+C stops delivery and drains collection locally.");
    Console.WriteLine("Live delivery includes signed heartbeat audits. --health reads signed central health without changing liveness. --no-audits disables live auditing.");
    Console.WriteLine("Collector file I/O is filtered before the queue. Desktop-managed process lifetimes are also filtered by default; process lifecycle events and other processes remain monitored. Standalone hosts can repeat --exclude-file-process for explicitly selected live peers.");
    return 0;
}
CollectorCommandLine options;
try { options = CollectorCommandLine.Parse(args); }
catch (ArgumentException error)
{
    Console.Error.WriteLine(error.Message);
    return 1;
}
bool inspect = options.Inspect, sendOnly = options.SendOnly, readHealth = options.ReadHealth, noAudits = options.NoAudits;
args = options.Positional;
TelemetryMonitor? monitor = null;
TelemetryDispatcher? dispatcher = null;
HeartbeatAuditAgent? auditAgent = null;
try
{
    using var fileIo = new ProcessFileIoFilter(Environment.ProcessId);
    var additional = options.AdditionalFileIoProcessIds.Select(id =>
    {
        using var process = Process.GetProcessById(id);
        return FileIoProcessIdentity.Capture(process);
    }).ToArray();
    void UpdateFileIo(string? policy)
    {
        var managed = options.ExcludeManagedFileIo && policy is not null
            ? JsonSerializer.Deserialize<FileIoProcessIdentity[]>(policy) ?? throw new ArgumentException("Missing file-I/O process policy.")
            : [];
        fileIo.Update(managed.Concat(additional).DistinctBy(p => p.ProcessId).ToArray());
    }
    UpdateFileIo(Environment.GetEnvironmentVariable(LocalProcessControl.FileIoProcessesVariable));
    Console.WriteLine($"File-I/O policy: collector PID={Environment.ProcessId}; managed process lifetimes={fileIo.ManagedProcessCount}.");
    if ((sendOnly || readHealth) && !File.Exists(args[1])) throw new FileNotFoundException("The existing outbox was not found. Use --inspect to initialize a new ledger explicitly.", args[1]);
    using var nodeKey = ECDsa.Create();
    nodeKey.ImportFromPem(await File.ReadAllTextAsync(args[2]));
    using var receiverKey = ECDsa.Create();
    receiverKey.ImportFromPem(await File.ReadAllTextAsync(args[3]));
    using var node = new EcdsaSignatureProvider(nodeKey, Fingerprint(nodeKey));
    using var receiver = new EcdsaSignatureProvider(receiverKey, Fingerprint(receiverKey));
    var retention = options.LoadRetention();
    if ((options.Retain || options.Compact) && !File.Exists(args[1])) throw new FileNotFoundException("Maintenance requires an existing outbox.", args[1]);
    await using var cache = await DurableTelemetryCache.OpenAsync(new() { NodeId = args[0], DatabasePath = args[1],
        MaximumStoredPayloadBytes = options.MaximumStoredPayloadBytes, Retention = retention }, node, node, receiver);
    Console.WriteLine($"Outbox: {(await cache.GetStatusAsync()).Checkpoint}");
    Console.WriteLine($"Storage: {await cache.GetStorageStatusAsync()}");
    if (inspect) return 0;
    if (options.Retain) { if (!retention.Enabled) throw new ArgumentException("Enable retention explicitly in --retention-config first."); Console.WriteLine(await cache.ApplyRetentionAsync()); return 0; }
    if (options.Compact) { await cache.CompactAsync(); Console.WriteLine("Cache compaction completed; verified archive history retained."); return 0; }
    using var http = args.Length == 6 && args[4] == "http" ? new HttpTelemetryTransport(new Uri(args[5]), receiver) : null;
    await using var grpc = args.Length == 6 && args[4] == "grpc" ? new GrpcTelemetryTransport(new Uri(args[5]), receiver) : null;
    using var httpAudits = args.Length == 6 && args[4] == "http" && (!noAudits || readHealth)
        ? new HttpHeartbeatAuditTransport(new Uri(args[5]), receiver) : null;
    using var grpcAudits = args.Length == 6 && args[4] == "grpc" && (!noAudits || readHealth)
        ? new GrpcHeartbeatAuditTransport(new Uri(args[5]), receiver) : null;
    IHeartbeatAuditTransport? auditTransport = httpAudits is not null ? httpAudits : grpcAudits;
    ITelemetryTransport? transport = http is not null ? http : grpc;
    if (transport is not null) dispatcher = new TelemetryDispatcher(cache, transport);
    using var shutdown = new CancellationTokenSource();
    await using var desktopControl = LocalProcessControl.FromEnvironment(shutdown.Cancel, policy => UpdateFileIo(policy));
    ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; shutdown.Cancel(); };
    Console.CancelKeyPress += cancel;
    try
    {
        if (sendOnly)
        {
            while (await dispatcher!.DispatchPendingAsync(shutdown.Token) > 0) { }
            Console.WriteLine($"Delivery: {dispatcher.GetHealth()}");
            if (retention.Enabled) Console.WriteLine($"Retention: {await cache.ApplyRetentionAsync(shutdown.Token)}");
            return 0;
        }
        if (readHealth)
        {
            var identity = (await cache.GetStatusAsync()).Checkpoint;
            auditAgent = new(identity.NodeId, identity.LedgerId, cache,
                () => new MonitorHealth(MonitorState.Stopped, 0, 0, 0, 0, 0, 0, 0, null), auditTransport!, node, receiver);
            var report = (await auditAgent.RefreshHealthAsync(shutdown.Token)).Content;
            Console.WriteLine($"Monitoring health: {report.Assessment.State}, score={report.Assessment.Score?.ToString() ?? "unknown"}, last-audit={report.LastAcceptedAuditUtc}, findings={string.Join(", ", report.Assessment.Findings)}");
            return 0;
        }
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Kernel ETW collection requires Windows.");
        if (retention.Enabled) Console.WriteLine($"Initial retention: {await cache.ApplyRetentionAsync(shutdown.Token)}");
        monitor = new TelemetryMonitor(new WindowsEtwTelemetrySource(new()
        {
            ExcludeCollectorProcess = false, // Count intentional file-I/O filtering in monitor health.
            RetainFileIoProcess = fileIo.RetainProcess,
            BufferSizeMegabytes = options.EtwBufferMegabytes
        }), cache, options.Monitor);
        if (auditTransport is not null)
        {
            var identity = (await cache.GetStatusAsync()).Checkpoint;
            auditAgent = new(identity.NodeId, identity.LedgerId, cache, monitor.GetHealth, auditTransport, node, receiver);
        }
        var collection = monitor.RunAsync(shutdown.Token);
        var delivery = dispatcher?.RunAsync(shutdown.Token) ?? Task.CompletedTask;
        var auditing = auditAgent?.RunAsync(shutdown.Token) ?? Task.CompletedTask;
        var retaining = retention.Enabled ? cache.RunRetentionAsync(message => Console.WriteLine("Retention: " + message), shutdown.Token) : null;
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
            while (!collection.IsCompleted && (dispatcher is null || !delivery.IsCompleted) && (auditAgent is null || !auditing.IsCompleted) && (retaining is null || !retaining.IsCompleted))
            {
                var tick = timer.WaitForNextTickAsync().AsTask();
                if (await Task.WhenAny(collection, dispatcher is null ? collection : delivery, auditAgent is null ? collection : auditing, retaining ?? collection, tick) != tick) break;
                await tick;
                var health = monitor.GetHealth();
                var status = await cache.GetStatusAsync();
                Console.WriteLine($"{health.State}: received={health.ReceivedEvents}, filtered={health.FilteredEvents}, committed={health.PersistedEvents}, queue-dropped={health.QueueDroppedEvents}, ETW-lost={health.SourceLostEvents}, pending-blocks={status.PendingBlocks}");
                if (dispatcher is not null) Console.WriteLine($"Delivery: {dispatcher.GetHealth()}");
                if (auditAgent is not null)
                {
                    var audit = auditAgent.GetHealth();
                    Console.WriteLine($"Audits: accepted={audit.CompletedAudits}, last={audit.LastAcceptedUtc}, health={audit.LastHealth?.State}, score={audit.LastHealth?.Score}, error={audit.LastError}");
                }
            }
        }
        finally
        {
            await shutdown.CancelAsync();
            await Task.WhenAll(collection, delivery, auditing, retaining ?? Task.CompletedTask);
        }
        Console.WriteLine($"Final collection health: {monitor.GetHealth()}");
        Console.WriteLine($"Stopped. {(await cache.GetStatusAsync()).PendingBlocks} blocks remain pending for the next delivery run.");
    }
    finally { Console.CancelKeyPress -= cancel; }
    return 0;
}
catch (OperationCanceledException) when (sendOnly || readHealth)
{
    Console.WriteLine("Delivery canceled. Unsettled blocks remain in the outbox.");
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error.Message);
    if (monitor is not null) Console.Error.WriteLine($"Collection health: {monitor.GetHealth()}");
    if (dispatcher is not null) Console.Error.WriteLine($"Delivery health: {dispatcher.GetHealth()}");
    if (auditAgent is not null) Console.Error.WriteLine($"Audit health: {auditAgent.GetHealth()}");
    return 1;
}
static string Fingerprint(ECDsa key) => Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
