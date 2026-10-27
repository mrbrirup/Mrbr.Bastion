using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Ingestion;
using Mrbr.Bastion.Ingestion.AspNetCore;
using Mrbr.Bastion.Ingestion.Sqlite;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Auditing.AspNetCore;

namespace Mrbr.Bastion.Tests;

internal sealed class IngestionFixture : IAsyncDisposable
{
    public TestLedger Local { get; } = new();
    public DurableTelemetryCache Cache { get; private set; } = null!;
    public SignedTelemetryBlock First { get; private set; } = null!;
    public StaticNodeTrustStore Trust { get; private set; } = null!;
    public SqliteIngestionStore Store { get; private set; } = null!;
    public TelemetryIngestionService Service { get; private set; } = null!;
    public SqliteIngestionOptions Options => new() { DatabasePath = Path.Combine(Local.DirectoryPath, "central.db") };
    public static async Task<IngestionFixture> CreateAsync()
    {
        var fixture = new IngestionFixture();
        try
        {
            fixture.Cache = await fixture.Local.OpenAsync();
            fixture.First = await fixture.Cache.AppendAsync([TestLedger.Event(path: @"C:\audit\test.txt")]);
            fixture.Trust = new([new(fixture.First.Content.NodeId, fixture.First.Content.LedgerId, fixture.Local.Node)]);
            await fixture.ReopenStoreAsync();
            return fixture;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }
    public async Task ReopenStoreAsync(SqliteIngestionOptions? options = null)
    {
        if (Store is not null) await Store.DisposeAsync();
        Store = await SqliteIngestionStore.OpenAsync(options ?? Options, Trust, Local.Server);
        Service = new(Trust, Store, Local.Server, Local.Server);
    }
    public SignedTelemetryBlock Sign(TelemetryBlockContent content)
    {
        var bytes = LedgerProtocol.EncodeBlock(content);
        return new(content, Convert.ToHexString(SHA256.HashData(bytes)), Local.Node.Sign(bytes));
    }
    public async ValueTask DisposeAsync()
    {
        if (Store is not null) await Store.DisposeAsync();
        if (Cache is not null) await Cache.DisposeAsync();
        Local.Dispose();
    }
}

internal sealed class NetworkIngestionHost : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly X509Certificate2? _certificate;
    public Uri GrpcAddress { get; }
    public Mrbr.Bastion.Transport.TelemetryTransportOptions ClientOptions { get; }
    public Uri Address { get; }
    private NetworkIngestionHost(WebApplication app, X509Certificate2? certificate, Uri address, Uri grpcAddress)
    { _app = app; _certificate = certificate; Address = address; GrpcAddress = grpcAddress; ClientOptions = new() { AllowInsecureLoopback = certificate is null }; }
    public static async Task<NetworkIngestionHost> StartAsync(ITelemetryIngestor ingestor, bool useTls = false, bool? allowInsecureLoopback = null,
        IHeartbeatAuditService? auditService = null)
    {
        X509Certificate2? certificate = null;
        if (useTls)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder(); names.AddIpAddress(IPAddress.Loopback); names.AddDnsName("localhost");
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            // Schannel needs a named private key for server credential acquisition.
            // UserKeySet creates a temporary current-user container; no trust-store
            // entry or PersistKeySet is used, and host disposal releases the key.
            byte[] pfx = generated.Export(X509ContentType.Pkcs12);
            try
            {
                certificate = X509CertificateLoader.LoadPkcs12(pfx, null,
                    OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
            }
            finally { CryptographicOperations.ZeroMemory(pfx); }
        }
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o =>
        {
            o.Limits.MaxRequestBodySize = null;
            if (certificate is not null)
                o.Listen(IPAddress.Loopback, 0, listen => { listen.Protocols = HttpProtocols.Http1AndHttp2; listen.UseHttps(certificate); });
            else
            {
                o.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http1);
                o.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http2);
            }
        });
        builder.Services.AddSingleton(ingestor);
        builder.Services.AddBastionIngestionEndpoints(new() { AllowInsecureLoopback = allowInsecureLoopback ?? !useTls });
        if (auditService is not null)
        {
            builder.Services.AddSingleton(auditService);
            builder.Services.AddBastionAuditEndpoints(new() { AllowInsecureLoopback = allowInsecureLoopback ?? !useTls });
        }
        var app = builder.Build();
        app.UseRateLimiter(); app.MapBastionIngestion();
        if (auditService is not null) app.MapBastionAudits();
        try
        {
            await app.StartAsync();
            var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses;
            var bound = addresses.ToArray();
            return new(app, certificate, new Uri(bound[0]), new Uri(bound[useTls ? 0 : 1]));
        }
        catch { await app.DisposeAsync(); certificate?.Dispose(); throw; }
    }
    // Test-only trust is pinned to this fixture's certificate; no global TLS bypass is installed.
    public HttpClientHandler Handler() => new()
    {
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = (_, certificate, _, _) => _certificate is not null && certificate?.Thumbprint == _certificate.Thumbprint
    };
    public HttpClient Client() => new(Handler()) { BaseAddress = Address };
    public async ValueTask DisposeAsync() { await _app.StopAsync(); await _app.DisposeAsync(); _certificate?.Dispose(); }
}

internal sealed class DelegateIngestor(Func<SignedTelemetryBlock, CancellationToken, Task<SettlementReceipt>> accept) : ITelemetryIngestor
{
    public Task<SettlementReceipt> IngestAsync(SignedTelemetryBlock block, CancellationToken cancellationToken = default) => accept(block, cancellationToken);
}
