using System.Net;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Transport;
using Mrbr.Bastion.Transport.Http;
using Mrbr.Bastion.Transport.Grpc;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class DeliveryWorkerTests
{
    [Fact]
    public async Task TransientFailureRetriesAndThenSettlesDurably()
    {
        await using var f = await IngestionFixture.CreateAsync();
        int attempts = 0;
        var transport = new DelegateTransport((block, token) => Interlocked.Increment(ref attempts) == 1
            ? Task.FromException<SettlementReceipt>(new TelemetryTransportException("offline", true))
            : f.Service.IngestAsync(block, token));
        var worker = new TelemetryDispatcher(f.Cache, transport, new()
        {
            InitialRetryDelay = TimeSpan.FromMilliseconds(10), MaximumRetryDelay = TimeSpan.FromMilliseconds(20), IdleInterval = TimeSpan.FromMilliseconds(10)
        });
        using var stop = new CancellationTokenSource();
        var run = worker.RunAsync(stop.Token);
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (worker.GetHealth().SettledBlocks == 0) await Task.Delay(10, deadline.Token);
        }
        finally { await stop.CancelAsync(); await run; }
        Assert.Equal(2, attempts);
        Assert.Equal(1, worker.GetHealth().TransientFailures);
        Assert.Null(worker.GetHealth().LastError);
        Assert.Empty(await f.Cache.ReadPendingAsync());
    }
    [Fact]
    public async Task PermanentFailureFaultsWithoutRetryingOrSettling()
    {
        await using var f = await IngestionFixture.CreateAsync();
        int attempts = 0;
        var transport = new DelegateTransport((_, _) =>
        { Interlocked.Increment(ref attempts); throw new TelemetryTransportException("untrusted receiver", false); });
        var worker = new TelemetryDispatcher(f.Cache, transport);
        Assert.False((await Assert.ThrowsAsync<TelemetryTransportException>(() => worker.RunAsync())).IsTransient);
        Assert.Equal(1, attempts);
        Assert.Single(await f.Cache.ReadPendingAsync());
    }
    [Fact]
    public async Task HttpTimeoutLeavesEvidencePendingAndIsClassifiedForRetry()
    {
        await using var f = await IngestionFixture.CreateAsync();
        using var transport = new HttpTelemetryTransport(new Uri("https://localhost"), f.Local.Server,
            new() { RequestTimeout = TimeSpan.FromMilliseconds(25) }, new HangingHandler());
        var worker = new TelemetryDispatcher(f.Cache, transport);
        Assert.True((await Assert.ThrowsAsync<TelemetryTransportException>(() => worker.DispatchPendingAsync())).IsTransient);
        Assert.Single(await f.Cache.ReadPendingAsync());
    }
    [Fact]
    public async Task CleartextCannotBeEnabledBySpoofingForwardedHeaders()
    {
        await using var f = await IngestionFixture.CreateAsync();
        await using var host = await NetworkIngestionHost.StartAsync(f.Service, allowInsecureLoopback: false);
        using var client = host.Client();
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/telemetry/blocks") { Content = new ByteArrayContent(TelemetryJson.Encode(f.First)) };
        request.Content.Headers.ContentType = new("application/json");
        request.Headers.Add("X-Forwarded-Proto", "https");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.UpgradeRequired, response.StatusCode);
        await using var grpc = new GrpcTelemetryTransport(host.GrpcAddress, f.Local.Server, host.ClientOptions, httpClient: client);
        Assert.False((await Assert.ThrowsAsync<TelemetryTransportException>(() => grpc.SubmitAsync(f.First))).IsTransient);
        Assert.Null(await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId));
    }
    private sealed class HangingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        { await Task.Delay(Timeout.Infinite, token); throw new InvalidOperationException("Unreachable"); }
    }
    private sealed class DelegateTransport(Func<SignedTelemetryBlock, CancellationToken, Task<SettlementReceipt>> send) : ITelemetryTransport
    {
        public Task<SettlementReceipt> SubmitAsync(SignedTelemetryBlock block, CancellationToken cancellationToken = default) => send(block, cancellationToken);
    }
}
