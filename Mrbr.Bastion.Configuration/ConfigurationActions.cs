using System.Security.Cryptography;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Cache;
using EcdsaSignatureProvider = Mrbr.Bastion.Cryptography.EcdsaSignatureProvider;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Notifications.Smtp;
using Mrbr.Bastion.Notifications.Webhooks;
using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.Security;
using Mrbr.Bastion.Operators.Sqlite;
using Mrbr.Bastion.Server;
using Mrbr.Bastion.Transport;
using Mrbr.Bastion.Core;

namespace Mrbr.Bastion.Configuration;

public static class ConfigurationActions
{
    public static void Validate(LauncherProfile p, bool checkFiles)
    {
        if (!Path.IsPathFullyQualified(p.DeploymentDirectory)) throw new ArgumentException("DeploymentDirectory must be absolute.");
        if (p.SelectedRunDurationSeconds is < 0 or > 86400) throw new ArgumentException("Selected run duration must be between 0 and 86,400 seconds.");
        if (p.RunInventory) p.Inventory.Validate();
        if (p.RunCollector)
        {
            if (string.IsNullOrWhiteSpace(p.Collector.NodeId) || p.Collector.NodeId.Length > 256
                || p.Collector.Transport is not ("http" or "grpc")) throw new ArgumentException("Configure a collector node ID and http/grpc transport.");
            new TelemetryTransportOptions().ValidateAddress(new Uri(p.Collector.ServiceUri));
            new TelemetryMonitorOptions { QueueCapacity = p.Collector.QueueCapacity, BatchSize = p.Collector.BatchSize,
                FlushInterval = TimeSpan.FromMilliseconds(p.Collector.FlushIntervalMilliseconds) }.Validate();
            if (p.Collector.BatchSize > 1000) throw new ArgumentException("The collector's durable cache supports batches of at most 1,000 events.");
            if (p.Collector.EtwBufferSizeMegabytes is < 1 or > 1024) throw new ArgumentException("ETW buffer size must be between 1 and 1024 MB.");
            new DurableCacheOptions { NodeId=p.Collector.NodeId,DatabasePath=p.Resolve(p.Collector.CacheDatabasePath),
                MaximumStoredPayloadBytes=p.Collector.MaximumStoredPayloadBytes,Retention=p.Collector.Retention }.Validate();
        }
        if (p.RunInventory && p.Inventory.ServiceUri is { } address)
            new TelemetryTransportOptions { AllowInsecureLoopback = p.Inventory.AllowInsecureLoopback }.ValidateAddress(new Uri(address));
        if (p.RunReceiver)
        {
            if (!Uri.TryCreate(p.Receiver.Kestrel.Endpoints.Https.Url, UriKind.Absolute, out var endpoint) || endpoint.Scheme != "https")
                throw new ArgumentException("The desktop receiver requires an absolute HTTPS listen URL.");
            if (p.Receiver.Kestrel.Endpoints.Https.Protocols is not ("Http1AndHttp2" or "Http1" or "Http2"))
                throw new ArgumentException("Choose Http1AndHttp2, Http1, or Http2 for the receiver endpoint.");
            p.Receiver.Bastion.Software.Validate();
            foreach (var route in p.Receiver.Bastion.Notifications.Email) using (new SmtpNotificationTransport(route)) { }
            foreach (var route in p.Receiver.Bastion.Notifications.Webhooks) using (new WebhookNotificationTransport(route)) { }
            if (checkFiles) using (ServerKeyMaterial.Load(p.Receiver.Bastion, p.DeploymentDirectory)) { }
            if (checkFiles && p.Receiver.Kestrel.Endpoints.Https.Certificate.Path is { Length: > 0 } certificate && !File.Exists(p.Resolve(certificate)))
                throw new FileNotFoundException("HTTPS certificate file is missing.");
        }
        var databases = new List<string>();
        if (p.RunCollector) databases.Add(p.Resolve(p.Collector.CacheDatabasePath));
        if (p.RunInventory) { databases.Add(p.Resolve(p.Inventory.CacheDatabasePath)); databases.Add(p.Resolve(p.Inventory.CrawlerDatabasePath)); }
        if (p.RunReceiver)
        {
            var b = p.Receiver.Bastion;
            foreach (var path in new[] { b.DatabasePath, b.AuditDatabasePath ?? b.DatabasePath + ".audits.db",
                b.Dashboard.DatabasePath ?? b.DatabasePath + ".alerts.db", b.Dashboard.OperatorDatabasePath ?? b.DatabasePath + ".operators.db",
                b.Notifications.DatabasePath ?? b.DatabasePath + ".notifications.db", b.Software.InventoryDatabasePath ?? b.DatabasePath + ".inventory.db",
                b.Software.ExposureDatabasePath ?? b.DatabasePath + ".exposures.db" }) databases.Add(p.Resolve(path));
        }
        if (databases.Distinct(StringComparer.OrdinalIgnoreCase).Count() != databases.Count)
            throw new ArgumentException("Each runtime database must have a distinct path.");
        foreach (RunTarget target in Enum.GetValues<RunTarget>())
        {
            if (!Selected(p, target)) continue;
            if (checkFiles) _ = RunPlan.Create(p, target);
        }
    }

    public static bool Selected(LauncherProfile p, RunTarget target) => target switch
    { RunTarget.Receiver => p.RunReceiver, RunTarget.Collector => p.RunCollector, _ => p.RunInventory };

    public static async Task<LedgerCheckpoint[]> InitializeLedgersAsync(LauncherProfile p)
    {
        Validate(p, checkFiles: false);
        var checkpoints = new List<LedgerCheckpoint>();
        async Task<LedgerCheckpoint> Initialize(string nodeId, string database, string privatePath, string receiverPath, bool inventory, long maximum, CacheRetentionOptions retention)
        {
            using var nodeKey = ECDsa.Create(); nodeKey.ImportFromPem(File.ReadAllText(p.Resolve(privatePath)));
            using var publicKey = ECDsa.Create(); publicKey.ImportFromPem(File.ReadAllText(p.Resolve(p.Keys.Node.PublicKeyPath)));
            if (!nodeKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(publicKey.ExportSubjectPublicKeyInfo()))
                throw new CryptographicException("The agent private key does not match Signing keys → Node → Public key path. Enroll custom independent agent keys explicitly on the receiver.");
            using var receiverKey = ECDsa.Create(); receiverKey.ImportFromPem(File.ReadAllText(p.Resolve(receiverPath)));
            using var node = new EcdsaSignatureProvider(nodeKey, EcdsaSignatureProvider.Fingerprint(nodeKey));
            using var receiver = new EcdsaSignatureProvider(receiverKey, EcdsaSignatureProvider.Fingerprint(receiverKey));
            await using var cache = await DurableTelemetryCache.OpenAsync(new() { NodeId = nodeId, DatabasePath = p.Resolve(database),
                MaximumStoredPayloadBytes = maximum, Retention = retention, AdditionalPayloadCodecs = inventory ? [new InventoryPayloadCodec()] : [] }, node, node, receiver);
            return (await cache.GetStatusAsync()).Checkpoint;
        }
        if (p.RunCollector)
        {
            checkpoints.Add(await Initialize(p.Collector.NodeId, p.Collector.CacheDatabasePath, p.Collector.NodePrivateKeyPath, p.Collector.ReceiverPublicKeyPath, false, p.Collector.MaximumStoredPayloadBytes, p.Collector.Retention));
        }
        if (p.RunInventory)
        {
            checkpoints.Add(await Initialize(p.Inventory.NodeId, p.Inventory.CacheDatabasePath, p.Inventory.NodePrivateKeyPath, p.Inventory.ReceiverPublicKeyPath, true, p.Inventory.MaximumStoredPayloadBytes, p.Inventory.Retention));
        }
        var nodes = p.Receiver.Bastion.Nodes.ToList();
        foreach (var checkpoint in checkpoints)
        {
            var existing = nodes.SingleOrDefault(n => n.NodeId == checkpoint.NodeId && n.LedgerId == checkpoint.LedgerId);
            if (existing is not null) continue; // Preserve explicit historical trust and key rotation configuration.
            nodes.Add(new() { NodeId = checkpoint.NodeId, LedgerId = checkpoint.LedgerId,
                DisplayName = checkpoint.NodeId + (checkpoint.NodeId == p.Collector.NodeId && checkpoint.LedgerId == checkpoints[0].LedgerId && p.RunCollector ? " · telemetry" : " · inventory"),
                PublicKeys = [new() { Path = p.Keys.Node.PublicKeyPath }] });
        }
        p.Receiver.Bastion.Nodes = nodes.ToArray();
        return checkpoints.ToArray();
    }

    public static async Task<string[]> MaintainCachesAsync(LauncherProfile p, string operation)
    {
        if (operation is not ("verify" or "retain" or "compact")) throw new ArgumentException("Unknown cache maintenance operation.");
        Validate(p, checkFiles: false); var results = new List<string>();
        async Task Maintain(string label, string nodeId, string database, string privatePath, string receiverPath, long maximum, CacheRetentionOptions retention, bool inventory)
        {
            string path = p.Resolve(database);
            if (!File.Exists(path)) throw new FileNotFoundException("Initialize the selected cache before maintenance.", path);
            using var nodeKey = ECDsa.Create(); nodeKey.ImportFromPem(await File.ReadAllTextAsync(p.Resolve(privatePath)));
            using var receiverKey = ECDsa.Create(); receiverKey.ImportFromPem(await File.ReadAllTextAsync(p.Resolve(receiverPath)));
            using var node = new EcdsaSignatureProvider(nodeKey, EcdsaSignatureProvider.Fingerprint(nodeKey));
            using var receiver = new EcdsaSignatureProvider(receiverKey, EcdsaSignatureProvider.Fingerprint(receiverKey));
            await using var cache = await DurableTelemetryCache.OpenAsync(new() { NodeId=nodeId,DatabasePath=path,MaximumStoredPayloadBytes=maximum,
                Retention=retention,AdditionalPayloadCodecs=inventory?[new InventoryPayloadCodec()]:[] }, node,node,receiver);
            if (operation == "retain")
            {
                var result = await cache.ApplyRetentionAsync();
                results.Add($"{label}: archived {result.ArchivedBlocks} settled blocks in {result.NewSegments} segments; retention enabled={retention.Enabled}.");
            }
            if (operation == "compact") await cache.CompactAsync();
            results.Add($"{label}: verified {await cache.GetStatusAsync()}; storage {await cache.GetStorageStatusAsync()}");
        }
        if (p.RunCollector) await Maintain("Collector",p.Collector.NodeId,p.Collector.CacheDatabasePath,p.Collector.NodePrivateKeyPath,p.Collector.ReceiverPublicKeyPath,p.Collector.MaximumStoredPayloadBytes,p.Collector.Retention,false);
        if (p.RunInventory) await Maintain("Inventory",p.Inventory.NodeId,p.Inventory.CacheDatabasePath,p.Inventory.NodePrivateKeyPath,p.Inventory.ReceiverPublicKeyPath,p.Inventory.MaximumStoredPayloadBytes,p.Inventory.Retention,true);
        if (results.Count == 0) throw new InvalidOperationException("Select the collector or inventory cache in Workspace.");
        return results.ToArray();
    }

    public static async Task BootstrapAdministratorAsync(LauncherProfile p, string username, string password)
    {
        var settings = p.Receiver.Bastion.Dashboard;
        if (settings.AuthenticationMode != Mrbr.Bastion.Operators.AspNetCore.OperatorAuthenticationMode.Users)
            throw new InvalidOperationException("Choose Users authentication before creating an administrator.");
        await using var store = SqliteOperatorStore.Open(new() { DatabasePath = p.Resolve(settings.OperatorDatabasePath ?? p.Receiver.Bastion.DatabasePath + ".operators.db"),
            MaximumUsers = settings.MaximumUsers, MaximumSecurityEvents = settings.MaximumSecurityEvents, MaximumSessions = settings.MaximumOperatorSessions });
        await new OperatorAccounts(store).CreateAsync(username, username, [OperatorRole.Administrator], password, bootstrap: true);
    }
}
