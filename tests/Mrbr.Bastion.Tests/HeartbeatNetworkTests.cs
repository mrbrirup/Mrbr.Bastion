using System.Net;
using global::Grpc.Core;
using global::Grpc.Net.Client;
using Google.Protobuf;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Grpc.Protocol;
using Mrbr.Bastion.Transport.Http;
using Mrbr.Bastion.Transport.Grpc;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class HeartbeatNetworkTests
{
    [Theory]
    [InlineData("http")]
    [InlineData("grpc")]
    public async Task RealNetworkAuditsVerifyAndReturnSignedCentralHealth(string protocol)
    {
        await using var f = await AuditFixture.CreateAsync();
        await using var host = await NetworkIngestionHost.StartAsync(f.Ledger.Service, auditService: f.Service);
        using var http = new HttpHeartbeatAuditTransport(host.Address, f.Ledger.Local.Server, host.ClientOptions, host.Handler());
        using var client = host.Client();
        using var grpc = new GrpcHeartbeatAuditTransport(host.GrpcAddress, f.Ledger.Local.Server, host.ClientOptions, client);
        var agent = f.Agent(protocol == "http" ? http : grpc);
        await agent.AuditOnceAsync();
        var health = await agent.RefreshHealthAsync();
        Assert.Equal(100, health.Content.Assessment.Score); Assert.Equal(ServerHealthState.Healthy, health.Content.Assessment.State);
        Assert.Equal(1, agent.GetHealth().CompletedAudits); Assert.Single(await f.Ledger.Cache.ReadPendingAsync());
        f.Clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(ServerHealthState.Offline, (await agent.RefreshHealthAsync()).Content.Assessment.State);
    }
    [Theory]
    [InlineData("http")]
    [InlineData("grpc")]
    public async Task TransportPreservesExpiredAndOutstandingChallengeSemantics(string protocol)
    {
        await using var f = await AuditFixture.CreateAsync();
        await using var host = await NetworkIngestionHost.StartAsync(f.Ledger.Service, auditService: f.Service);
        using var http = new HttpHeartbeatAuditTransport(host.Address, f.Ledger.Local.Server, host.ClientOptions, host.Handler());
        using var client = host.Client(); using var grpc = new GrpcHeartbeatAuditTransport(host.GrpcAddress, f.Ledger.Local.Server, host.ClientOptions, client);
        IHeartbeatAuditTransport transport = protocol == "http" ? http : grpc;
        var challenge = await transport.CreateChallengeAsync(f.Request());
        Assert.Equal(AuditFailure.ChallengeOutstanding, (await Assert.ThrowsAsync<AuditRejectedException>(() => transport.CreateChallengeAsync(f.Request()))).Failure);
        var response = await f.ResponseAsync(challenge); f.Clock.Advance(TimeSpan.FromSeconds(60));
        Assert.Equal(AuditFailure.ChallengeExpired, (await Assert.ThrowsAsync<AuditRejectedException>(() => transport.SubmitAsync(response))).Failure);
        Assert.Null(await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId));
    }
    [Fact]
    public async Task HttpAndGrpcAdaptersIndependentlyRejectForgedServerChallenges()
    {
        await using var f = await AuditFixture.CreateAsync();
        var forged = new AuditTransportDecorator(f.Service)
        {
            OnChallenge = async (request, token) =>
            {
                var challenge = await f.Service.CreateChallengeAsync(request, token); challenge.Signature[0] ^= 1; return challenge;
            }
        };
        await using var host = await NetworkIngestionHost.StartAsync(f.Ledger.Service, auditService: forged);
        using var http = new HttpHeartbeatAuditTransport(host.Address, f.Ledger.Local.Server, host.ClientOptions, host.Handler());
        var request = f.Request();
        Assert.False((await Assert.ThrowsAsync<TelemetryTransportException>(() => http.CreateChallengeAsync(request))).IsTransient);
        using var client = host.Client(); using var grpc = new GrpcHeartbeatAuditTransport(host.GrpcAddress, f.Ledger.Local.Server, host.ClientOptions, client);
        Assert.False((await Assert.ThrowsAsync<TelemetryTransportException>(() => grpc.CreateChallengeAsync(request))).IsTransient);
        Assert.Null(await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId));
    }
    [Fact]
    public async Task HttpHealthReadsRequireAnEnrolledNodeSignatureAndRejectOversizedBodies()
    {
        await using var f = await AuditFixture.CreateAsync();
        await using var host = await NetworkIngestionHost.StartAsync(f.Ledger.Service, auditService: f.Service);
        using var client = host.Client();
        var query = f.Query(); query.Signature[0] ^= 1;
        using var invalid = new ByteArrayContent(TelemetryJson.Encode(query)); invalid.Headers.ContentType = new("application/json");
        using var response = await client.PostAsync("api/v1/audits/health", invalid);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var large = new ByteArrayContent(new byte[AuditProtocol.MaximumEnvelopeBytes + 1]); large.Headers.ContentType = new("application/json");
        using var rejection = await client.PostAsync("api/v1/audits/challenges", large);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, rejection.StatusCode);
        Assert.Null(await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId));
    }
    [Fact]
    public async Task MalformedGrpcAuditDocumentsAreRejectedWithoutUpdatingHealth()
    {
        await using var f = await AuditFixture.CreateAsync();
        await using var host = await NetworkIngestionHost.StartAsync(f.Ledger.Service, auditService: f.Service);
        using var http = host.Client(); using var channel = GrpcChannel.ForAddress(host.GrpcAddress, new GrpcChannelOptions { HttpClient = http });
        var client = new HeartbeatAudits.HeartbeatAuditsClient(channel);
        using var call = client.SubmitAuditAsync(new AuditDocument { Document = ByteString.CopyFromUtf8("null") });
        Assert.Equal(StatusCode.InvalidArgument, (await Assert.ThrowsAsync<RpcException>(() => call.ResponseAsync)).StatusCode);
        Assert.Null(await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId));
    }
    [Fact]
    public async Task CleartextAuditEndpointsRemainDisabledWithoutExplicitLoopbackOptIn()
    {
        await using var f = await AuditFixture.CreateAsync();
        await using var host = await NetworkIngestionHost.StartAsync(f.Ledger.Service, allowInsecureLoopback: false, auditService: f.Service);
        using var http = new HttpHeartbeatAuditTransport(host.Address, f.Ledger.Local.Server, host.ClientOptions, host.Handler());
        Assert.False((await Assert.ThrowsAsync<TelemetryTransportException>(() => http.CreateChallengeAsync(f.Request()))).IsTransient);
        using var client = host.Client(); using var grpc = new GrpcHeartbeatAuditTransport(host.GrpcAddress, f.Ledger.Local.Server, host.ClientOptions, client);
        Assert.False((await Assert.ThrowsAsync<TelemetryTransportException>(() => grpc.CreateChallengeAsync(f.Request()))).IsTransient);
    }
}
