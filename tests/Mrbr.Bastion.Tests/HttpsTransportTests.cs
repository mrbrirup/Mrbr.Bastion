using Mrbr.Bastion.Transport;
using Mrbr.Bastion.Transport.Http;
using Mrbr.Bastion.Transport.Grpc;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class HttpsTransportTests
{
    [TlsFact]
    [Trait("Category", "TLS")]
    public async Task HttpsAndHttp2UseTheSameCertificatePinnedEndpoint()
    {
        await using var audit = await AuditFixture.CreateAsync(ingestFirst: false);
        var f = audit.Ledger;
        await using var host = await NetworkIngestionHost.StartAsync(f.Service, useTls: true, auditService: audit.Service);
        using var http = new HttpTelemetryTransport(host.Address, f.Local.Server, handler: host.Handler());
        var receipt = await http.SubmitAsync(f.First);
        using var client = host.Client();
        await using var grpc = new GrpcTelemetryTransport(host.GrpcAddress, f.Local.Server, httpClient: client);
        var duplicate = await grpc.SubmitAsync(f.First);
        Assert.Equal(receipt.Signature, duplicate.Signature);
        Assert.Equal(1, await new TelemetryDispatcher(f.Cache, grpc).DispatchPendingAsync());
        Assert.Empty(await f.Cache.ReadPendingAsync());
        using var httpAudit = new HttpHeartbeatAuditTransport(host.Address, f.Local.Server, handler: host.Handler());
        await audit.Agent(httpAudit).AuditOnceAsync();
        using var grpcAudit = new GrpcHeartbeatAuditTransport(host.GrpcAddress, f.Local.Server, httpClient: client);
        Assert.Equal(100, (await audit.Agent(grpcAudit).RefreshHealthAsync()).Content.Assessment.Score);
    }
}
public sealed class TlsFactAttribute : FactAttribute
{
    public TlsFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("BASTION_RUN_TLS_TESTS") != "1")
            Skip = "Set BASTION_RUN_TLS_TESTS=1 in a test host with working OS TLS credentials. Restricted Windows tokens can fail Schannel credential acquisition.";
    }
}
