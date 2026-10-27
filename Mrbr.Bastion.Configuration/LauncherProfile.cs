using System.ComponentModel;
using System.Text.Json.Serialization;
using Mrbr.Bastion.Inventory.Agent;
using Mrbr.Bastion.Operators.AspNetCore;
using Mrbr.Bastion.Server;
using Mrbr.Bastion.Cache;

namespace Mrbr.Bastion.Configuration;

public enum RunTarget { Receiver, Collector, Inventory }
public enum BuildMode { Debug, Release }

public sealed class LauncherProfile
{
    [ReadOnly(true), Description("Profile format. Runtime state and secret values are not saved.")]
    public int Version { get; set; } = 1;
    [Description("Absolute folder for runtime configuration, data and relative key paths. Changing this does not move existing data.")]
    public string DeploymentDirectory { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mrbr.Bastion", "default");
    [Description("Source build locations or published executable overrides. Build the solution before starting.")]
    public RuntimeLocations Runtime { get; set; } = new();
    [Description("Persistent P-256 signing pairs. These are separate from the HTTPS certificate. Existing files are never overwritten.")]
    public RequiredKeys Keys { get; set; } = new();
    [Description("Complete receiver settings: HTTPS, enrollment, dashboard, CVE evaluation and notifications.")]
    public ReceiverDocument Receiver { get; set; } = new();
    [Description("Process/file telemetry and heartbeat auditing. Live collection requires Administrator privileges.")]
    public CollectorConfiguration Collector { get; set; } = new();
    [Description("Inventory settings. Enable ProcessEvents for live lineage. Choose crawler roots deliberately.")]
    public InventoryAgentSettings Inventory { get; set; } = new()
    {
        NodeId = "server-01", CacheDatabasePath = "data/inventory-outbox.db", CrawlerDatabasePath = "data/inventory-crawlers.db",
        NodePrivateKeyPath = "keys/node-private.pem", ReceiverPublicKeyPath = "keys/receiver-public.pem", ServiceUri = "https://localhost:7443"
    };
    [Description("Include receiver in Start selected.")] public bool RunReceiver { get; set; } = true;
    [Description("Include process/file monitoring in Start selected.")] public bool RunCollector { get; set; } = true;
    [Description("Include inventory in Start selected. Inventory has a separate enrolled ledger.")] public bool RunInventory { get; set; } = true;
    [Description("Optional bounded Start selected run, in seconds (0 = continuous; maximum 86,400). Saves midpoint/final application screenshots and a local command log, then gracefully stops all components. Individual Start commands are not timed.")]
    public int SelectedRunDurationSeconds { get; set; }

    public string Resolve(string path) => Path.GetFullPath(path, Path.GetFullPath(DeploymentDirectory));
    [JsonIgnore, Browsable(false)] public string ReceiverFile => Resolve("server.json");
    [JsonIgnore, Browsable(false)] public string InventoryFile => Resolve("inventory.json");
    [JsonIgnore, Browsable(false)] public string RetentionFile => Resolve("collector-retention.local.json");
}

public sealed class RuntimeLocations
{
    [Description("Solution root containing Mrbr.Bastion.slnx. Used when an executable override is empty.")]
    public string SolutionDirectory { get; set; } = FindSolution();
    [Description("Must match the binaries built in Visual Studio.")]
    public BuildMode BuildConfiguration { get; set; } =
#if DEBUG
        BuildMode.Debug;
#else
        BuildMode.Release;
#endif
    [Description("dotnet command or absolute dotnet.exe path for framework-dependent DLLs.")]
    public string DotnetExecutable { get; set; } = "dotnet";
    [Description("Optional published .exe or .dll; empty uses the solution's server build.")]
    public string ReceiverExecutable { get; set; } = "";
    [Description("Optional published .exe or .dll; empty uses the solution's console build.")]
    public string CollectorExecutable { get; set; } = "";
    [Description("Optional published .exe or .dll; empty uses the solution's inventory build.")]
    public string InventoryExecutable { get; set; } = "";
    private static string FindSolution()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "Mrbr.Bastion.slnx"))) return directory.FullName;
        return "";
    }
}
public sealed class RequiredKeys
{
    public PemKeyPair Receiver { get; set; } = new() { PrivateKeyPath = "keys/receiver-private.pem", PublicKeyPath = "keys/receiver-public.pem" };
    public PemKeyPair Node { get; set; } = new() { PrivateKeyPath = "keys/node-private.pem", PublicKeyPath = "keys/node-public.pem" };
}
public sealed class PemKeyPair
{
    [ReadOnly(true), Description("P-256 ECDSA with PKCS#8 private PEM and SubjectPublicKeyInfo public PEM.")]
    public string Algorithm => "ECDSA P-256 / SHA-256";
    [Description("Private PEM save location, relative to DeploymentDirectory or absolute. Protect this file.")]
    public string PrivateKeyPath { get; set; } = "";
    [Description("Matching public PEM save location. Provision only the public key to the verifying machine.")]
    public string PublicKeyPath { get; set; } = "";
}
public sealed class ReceiverDocument
{
    public KestrelConfiguration Kestrel { get; set; } = new();
    public ServerSettings Bastion { get; set; } = new()
    {
        DatabasePath = "data/ingestion.db", ReceiptSigningPrivateKeyPath = "keys/receiver-private.pem",
        AuditDatabasePath = "data/audits.db",
        Software = new() { Enabled = true },
        Dashboard = new() { Enabled = true, AuthenticationMode = OperatorAuthenticationMode.Users,
            OperatorDatabasePath = "data/operators.db", DatabasePath = "data/alerts.db" }
    };
}
public sealed class KestrelConfiguration { public EndpointCollection Endpoints { get; set; } = new(); }
public sealed class EndpointCollection { public HttpsEndpoint Https { get; set; } = new(); }
public sealed class HttpsEndpoint
{
    [Description("Receiver listen address. Remote deployments need a reachable hostname, firewall rule and trusted certificate.")]
    public string Url { get; set; } = "https://localhost:7443";
    [Description("Http1AndHttp2 supports both HTTP and gRPC on HTTPS.")]
    public string Protocols { get; set; } = "Http1AndHttp2";
    [Description("Empty Path uses the current user's ASP.NET Core development certificate. Signing PEMs do not provide HTTPS.")]
    public CertificateConfiguration Certificate { get; set; } = new();
}
public sealed class CertificateConfiguration
{
    [Description("Optional HTTPS PFX file, relative to DeploymentDirectory or absolute.")]
    public string? Path { get; set; }
    [PasswordPropertyText(true), Description("Session-only PFX password. Omitted from saved files and passed to the child environment.")]
    public string? Password { get; set; }
}
public sealed class CollectorConfiguration
{
    [Description("Maximum resident payload bytes. Archive files, SQLite metadata, receipts and WAL require additional space. Unsettled evidence is never purged.")]
    public long MaximumStoredPayloadBytes { get; set; } = 512L * 1024 * 1024;
    [Description("Opt-in settled-prefix retention, archive location, recent window, segment limits and maintenance interval.")]
    public CacheRetentionOptions Retention { get; set; } = new();
    [Description("Stable monitored-system ID. Enroll this ID and the outbox ledger GUID at the receiver.")]
    public string NodeId { get; set; } = "server-01";
    public string CacheDatabasePath { get; set; } = "data/telemetry-outbox.db";
    public string NodePrivateKeyPath { get; set; } = "keys/node-private.pem";
    public string ReceiverPublicKeyPath { get; set; } = "keys/receiver-public.pem";
    [Description("HTTPS receiver address. localhost reaches this computer only.")]
    public string ServiceUri { get; set; } = "https://localhost:7443";
    [Description("http or grpc. gRPC requires HTTP/2 at the receiver.")]
    public string Transport { get; set; } = "http";
    [Description("Send an existing outbox without ETW. Does not generate live collection heartbeats.")]
    public bool SendOnly { get; set; }
    [Description("Send signed heartbeat audits during live collection.")]
    public bool Audits { get; set; } = true;
    [Description("Suppress file I/O from this control panel's explicitly managed process lifetimes. Process lifecycle events, descendants and other processes' access remain monitored. Filtered events are counted separately from losses.")]
    public bool ExcludeManagedProcessFileIo { get; set; } = true;
    [Description("Maximum queued retained events. Overflow is reported as event loss; filtering does not hide it. Range 1–1,000,000.")]
    public int QueueCapacity { get; set; } = 8192;
    [Description("Maximum events per durable batch, 1–1,000. Larger batches must still fit the payload byte limit.")]
    public int BatchSize { get; set; } = 100;
    [Description("Maximum wait to flush a partial batch, 1–60,000 milliseconds.")]
    public int FlushIntervalMilliseconds { get; set; } = 1000;
    [Description("Kernel ETW buffer size, 1–1,024 MB. ETW source losses remain separately reported.")]
    public int EtwBufferSizeMegabytes { get; set; } = 64;
}
