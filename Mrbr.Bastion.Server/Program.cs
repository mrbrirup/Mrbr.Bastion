using Microsoft.AspNetCore.Server.Kestrel.Core;
using Mrbr.Bastion.Ingestion;
using Mrbr.Bastion.Ingestion.AspNetCore;
using Mrbr.Bastion.Ingestion.Sqlite;
using Mrbr.Bastion.Server;
using Mrbr.Bastion.Auditing;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Auditing.AspNetCore;
using Mrbr.Bastion.Auditing.Sqlite;
using Mrbr.Bastion.Health;
using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Alerting.Sqlite;
using Mrbr.Bastion.Dashboard;
using Mrbr.Bastion.Operations;
using Mrbr.Bastion.Operations.Hosting;
using Mrbr.Bastion.Notifications.Hosting;
using Mrbr.Bastion.Notifications;
using Mrbr.Bastion.Notifications.Sqlite;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Vulnerabilities;
using Mrbr.Bastion.Vulnerabilities.Sqlite;
using Mrbr.Bastion.Vulnerabilities.Nvd;
using Mrbr.Bastion.Software.Hosting;
using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.Sqlite;
using Mrbr.Bastion.Operators.Security;
using Mrbr.Bastion.Operators.AspNetCore;

var bootstrap = new ConfigurationBuilder().AddCommandLine(args).Build();
string? config = bootstrap["config"] is { } path ? Path.GetFullPath(path) : null;
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{ Args = args, ContentRootPath = config is null ? null : Path.GetDirectoryName(config) });
if (config is not null) builder.Configuration.AddJsonFile(config, optional: false, reloadOnChange: false).AddEnvironmentVariables().AddCommandLine(args);
var settings = builder.Configuration.GetSection("Bastion").Get<ServerSettings>()
    ?? throw new InvalidOperationException("Configure the Bastion section using --config <file> or service configuration.");
if (settings.Dashboard.Enabled) builder.Services.AddBastionDashboard(new()
{
    AccessToken = settings.Dashboard.AccessToken,
    AuthenticationMode=settings.Dashboard.AuthenticationMode,SessionMinutes=settings.Dashboard.SessionMinutes,
    AllowInsecureLoopback = settings.AllowInsecureLoopback,
    AlertEvaluationIntervalSeconds = settings.Dashboard.AlertEvaluationIntervalSeconds
});
await using var operators=settings.Dashboard.Enabled&&settings.Dashboard.AuthenticationMode==OperatorAuthenticationMode.Users?SqliteOperatorStore.Open(new()
{
    DatabasePath=Path.GetFullPath(settings.Dashboard.OperatorDatabasePath??settings.DatabasePath+".operators.db",builder.Environment.ContentRootPath),
    MaximumUsers=settings.Dashboard.MaximumUsers,MaximumSecurityEvents=settings.Dashboard.MaximumSecurityEvents,MaximumSessions=settings.Dashboard.MaximumOperatorSessions
}):null;
if(operators is not null)
{
    builder.Services.AddSingleton<IOperatorStore>(operators);builder.Services.AddSingleton(new OperatorAccounts(operators));
    if((await operators.ReadUsersAsync(limit:1)).Users.Length==0)Console.Error.WriteLine("No operators are provisioned. Stop the server and use Mrbr.Bastion.Operators.Tool bootstrap with the configured operator database before signing in.");
}
using var keys = ServerKeyMaterial.Load(settings, builder.Environment.ContentRootPath);
await using var store = await SqliteIngestionStore.OpenAsync(new()
{
    DatabasePath = Path.GetFullPath(settings.DatabasePath, builder.Environment.ContentRootPath),
    MaximumStoredPayloadBytes = settings.MaximumStoredPayloadBytes,
    BlockLimits = new(){AdditionalPayloadCodecs=[new InventoryPayloadCodec()]}
}, keys.NodeTrust, keys.ReceiptVerifier);
bool operationsEnabled = settings.Dashboard.Enabled || settings.Notifications.Enabled || settings.Software.Enabled;
await using var alertStore = operationsEnabled ? await SqliteAlertStore.OpenAsync(new()
{
    DatabasePath = Path.GetFullPath(settings.Dashboard.DatabasePath ?? (settings.DatabasePath + ".alerts.db"), builder.Environment.ContentRootPath),
    MaximumStoredAlerts = settings.Dashboard.MaximumStoredAlerts
}) : null;
if (alertStore is not null)
{
    builder.Services.AddSingleton<IAlertStore>(alertStore);
    builder.Services.AddSingleton(new ServerInventory(settings.Nodes.Select(n => new MonitoredServer(n.NodeId, n.LedgerId, n.DisplayName ?? n.NodeId))));
    builder.Services.AddBastionOperations(new() { AlertEvaluationIntervalSeconds = settings.Dashboard.AlertEvaluationIntervalSeconds });
}
await using var auditStore = await SqliteHeartbeatAuditStore.OpenAsync(new()
{
    DatabasePath = Path.GetFullPath(settings.AuditDatabasePath ?? (settings.DatabasePath + ".audits.db"), builder.Environment.ContentRootPath),
    MaximumStoredAudits = settings.MaximumStoredAudits,
    MaximumStoredBytes = settings.MaximumStoredAuditBytes
}, keys.NodeTrust, keys.ReceiptVerifier);
if (operationsEnabled) builder.Services.AddSingleton<IAuditHistoryReader>(auditStore);
await using var notifications = settings.Notifications.Enabled
    ? await NotificationRuntime.OpenAsync(settings.Notifications, alertStore!, builder.Environment.ContentRootPath, settings.DatabasePath + ".notifications.db") : null;
if (notifications is not null) builder.Services.AddBastionNotifications(notifications.Dispatcher, notifications.Queue,
    new() { PollIntervalSeconds = settings.Notifications.PollIntervalSeconds });
string notificationDatabasePath = Path.GetFullPath(settings.Notifications.DatabasePath ?? (settings.DatabasePath + ".notifications.db"), builder.Environment.ContentRootPath);
await using var pausedNotifications = !settings.Notifications.Enabled && settings.Dashboard.Enabled && File.Exists(notificationDatabasePath)
    ? await SqliteNotificationQueue.OpenAsync(new() { DatabasePath = notificationDatabasePath }) : null;
if (pausedNotifications is not null) builder.Services.AddSingleton<INotificationReader>(pausedNotifications);
settings.Software.Validate();
await using var softwareInventory=settings.Software.Enabled?SqliteInventoryStore.Open(Path.GetFullPath(settings.Software.InventoryDatabasePath??settings.DatabasePath+".inventory.db",builder.Environment.ContentRootPath),settings.Software.MaximumItems):null;
await using var exposures=settings.Software.Enabled?SqliteExposureStore.Open(Path.GetFullPath(settings.Software.ExposureDatabasePath??settings.DatabasePath+".exposures.db",builder.Environment.ContentRootPath),settings.Software.MaximumFindings):null;
using var nvd=settings.Software.Enabled&&settings.Software.IntelligenceEnabled?new NvdClient(settings.Software.NvdApiKey):null;
if(softwareInventory is not null&&exposures is not null)
{
    var reviewed=await exposures.ReadMappingsAsync();
    foreach(var mapping in settings.Software.Mappings)
        if(reviewed.SingleOrDefault(m=>m.Id==mapping.Id) is not {} current||current.Revision<=mapping.Revision)await exposures.ReviewAsync(mapping);
    builder.Services.AddSingleton<IInventoryReader>(softwareInventory);builder.Services.AddSingleton<IExposureReader>(exposures);builder.Services.AddSingleton<IMappingReviewer>(exposures);
    builder.Services.AddSingleton<ICveEvidenceReader>(exposures);
    if(nvd is not null)builder.Services.AddSingleton<IVulnerabilityProvider>(nvd);
    builder.Services.AddSingleton(sp=>new SoftwareRuntime(store,softwareInventory,exposures,alertStore!,settings.Nodes.Select(n=>new SoftwareEnrollment(n.NodeId,n.LedgerId)).ToArray(),settings.Software,nvd,sp.GetRequiredService<ILogger<SoftwareRuntime>>()));
    builder.Services.AddSingleton<ISoftwareMonitor>(sp=>sp.GetRequiredService<SoftwareRuntime>());
    builder.Services.AddHostedService(sp=>sp.GetRequiredService<SoftwareRuntime>());
}
var scorer = new ServerHealthScorer(new()
{
    StaleAfter = TimeSpan.FromSeconds(settings.HeartbeatStaleAfterSeconds),
    OfflineAfter = TimeSpan.FromSeconds(settings.HeartbeatOfflineAfterSeconds)
});
var auditService = new HeartbeatAuditService(keys.NodeTrust, store, auditStore,
    keys.Signer, keys.ReceiptVerifier, scorer, new() { ChallengeLifetime = TimeSpan.FromSeconds(settings.AuditChallengeLifetimeSeconds) });
builder.Services.AddSingleton<IHeartbeatAuditService>(auditService);
builder.Services.AddSingleton<INodeHealthReader>(auditService);
builder.Services.AddBastionAuditEndpoints(new()
{ AllowInsecureLoopback = settings.AllowInsecureLoopback, MaximumConcurrentRequests = settings.MaximumConcurrentAuditRequests });
builder.Services.AddSingleton<ITelemetryIngestor>(new TelemetryIngestionService(keys.NodeTrust, store, keys.Signer, keys.ReceiptVerifier,
    new(){AdditionalPayloadCodecs=settings.Software.Enabled?[new InventoryPayloadCodec()]:[]}));
builder.Services.AddBastionIngestionEndpoints(new()
{ AllowInsecureLoopback = settings.AllowInsecureLoopback, MaximumConcurrentRequests = settings.MaximumConcurrentRequests,
    AdditionalPayloadFormats=settings.Software.Enabled?[Mrbr.Bastion.Abstraction.LedgerProtocol.InventoryPayloadFormat]:[] });
builder.WebHost.ConfigureKestrel(options =>
{
    // Duplex streams may contain many bounded protobuf messages; do not impose an aggregate stream body limit.
    options.Limits.MaxRequestBodySize = null;
    options.ConfigureEndpointDefaults(endpoint => endpoint.Protocols = HttpProtocols.Http1AndHttp2);
});
await using var app = builder.Build();
app.UseRateLimiter();
if (settings.Dashboard.Enabled) app.UseBastionDashboard();
app.MapBastionIngestion();
app.MapBastionAudits();
if (settings.Dashboard.Enabled)
{
    app.MapBastionDashboard();
    app.MapGet("/", () => Results.Redirect("/dashboard"));
}
await using var desktopControl = Mrbr.Bastion.Hosting.LocalProcessControl.FromEnvironment(app.Lifetime.StopApplication);
await app.RunAsync();
