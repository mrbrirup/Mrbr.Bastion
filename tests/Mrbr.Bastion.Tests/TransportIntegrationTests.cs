using System.Net;
using System.Net.Http.Headers;
using System.Text;
using global::Grpc.Core;
using global::Grpc.Net.Client;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Grpc;
using Mrbr.Bastion.Grpc.Protocol;
using Mrbr.Bastion.Transport;
using Mrbr.Bastion.Transport.Grpc;
using Mrbr.Bastion.Transport.Http;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class TransportIntegrationTests
{
    [Theory]
    [InlineData("http")]
    [InlineData("grpc")]
    [InlineData("grpc-unary")]
    public async Task RealNetworkTransportDeliversBlocksAndSettlesTheLocalOutbox(string protocol)
    {
        await using var f = await IngestionFixture.CreateAsync();
        await f.Cache.AppendAsync([TestLedger.Event(2)]);
        await f.Cache.AppendAsync([TestLedger.Event(3)]);
        await using var host = await NetworkIngestionHost.StartAsync(f.Service);
        using var http = new HttpTelemetryTransport(host.Address, f.Local.Server, host.ClientOptions, handler: host.Handler());
        using var client = host.Client();
        await using var grpc = new GrpcTelemetryTransport(host.GrpcAddress, f.Local.Server, host.ClientOptions, useStreaming: protocol != "grpc-unary", httpClient: client);
        ITelemetryTransport transport = protocol == "http" ? http : grpc;
        var dispatcher = new TelemetryDispatcher(f.Cache, transport);
        Assert.Equal(3, await dispatcher.DispatchPendingAsync());
        Assert.Empty(await f.Cache.ReadPendingAsync());
        Assert.Equal(3, dispatcher.GetHealth().SettledBlocks);
        var tip = await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId);
        Assert.Equal(3, tip!.SequenceNumber);
        await f.Store.VerifyIntegrityAsync();
    }

    [Theory]
    [InlineData("http")]
    [InlineData("grpc")]
    public async Task LostResponseCanBeRetriedAfterReceiverRestartWithoutDuplicatingEvidence(string protocol)
    {
        await using var f = await IngestionFixture.CreateAsync();
        SettlementReceipt original;
        await using (var host = await NetworkIngestionHost.StartAsync(f.Service))
        {
            using var http = new HttpTelemetryTransport(host.Address, f.Local.Server, host.ClientOptions, handler: host.Handler());
            using var client = host.Client();
            await using var grpc = new GrpcTelemetryTransport(host.GrpcAddress, f.Local.Server, host.ClientOptions, httpClient: client);
            ITelemetryTransport selected = protocol == "http" ? http : grpc;
            var dispatcher = new TelemetryDispatcher(f.Cache, new LostReplyTransport(selected));
            Assert.True((await Assert.ThrowsAsync<TelemetryTransportException>(() => dispatcher.DispatchPendingAsync())).IsTransient);
            Assert.Single(await f.Cache.ReadPendingAsync());
            original = (await f.Store.ReadAsync(f.First.Content.NodeId, f.First.Content.LedgerId, 1))!.Receipt;
        }
        await f.ReopenStoreAsync();
        await using var restarted = await NetworkIngestionHost.StartAsync(f.Service);
        using var httpRetry = new HttpTelemetryTransport(restarted.Address, f.Local.Server, restarted.ClientOptions, handler: restarted.Handler());
        using var retryClient = restarted.Client();
        await using var grpcRetry = new GrpcTelemetryTransport(restarted.GrpcAddress, f.Local.Server, restarted.ClientOptions, httpClient: retryClient);
        ITelemetryTransport retry = protocol == "http" ? httpRetry : grpcRetry;
        var receipt = await retry.SubmitAsync(f.First);
        Assert.Equal(original.Content, receipt.Content);
        Assert.Equal(original.Signature, receipt.Signature);
        Assert.Equal(1, await new TelemetryDispatcher(f.Cache, retry).DispatchPendingAsync());
        Assert.Empty(await f.Cache.ReadPendingAsync());
    }

    [Theory]
    [InlineData("http", false)]
    [InlineData("http", true)]
    [InlineData("grpc", false)]
    [InlineData("grpc", true)]
    public async Task ASuccessfulResponseCannotSettleAReceiptWithWrongSignatureOrIdentity(string protocol, bool wrongIdentity)
    {
        await using var f = await IngestionFixture.CreateAsync();
        var receipt = f.Local.Receipt(f.First);
        if (wrongIdentity) receipt = f.Local.Sign(receipt.Content with { BlockId = Guid.NewGuid() });
        else receipt.Signature[0] ^= 0xff;
        var forged = receipt;
        await using var host = await NetworkIngestionHost.StartAsync(new DelegateIngestor((_, _) => Task.FromResult(forged)));
        using var http = new HttpTelemetryTransport(host.Address, f.Local.Server, host.ClientOptions, handler: host.Handler());
        using var client = host.Client();
        await using var grpc = new GrpcTelemetryTransport(host.GrpcAddress, f.Local.Server, host.ClientOptions, httpClient: client);
        var dispatcher = new TelemetryDispatcher(f.Cache, protocol == "http" ? http : grpc);
        Assert.False((await Assert.ThrowsAsync<TelemetryTransportException>(() => dispatcher.DispatchPendingAsync())).IsTransient);
        Assert.Single(await f.Cache.ReadPendingAsync());
    }

    [Fact]
    public async Task HttpMapsAuthenticationOrderingAndMalformedRequestsWithoutReceipts()
    {
        await using var f = await IngestionFixture.CreateAsync();
        await using var host = await NetworkIngestionHost.StartAsync(f.Service);
        using var client = host.Client();
        var invalid = f.First with { Signature = new byte[64] };
        Assert.Equal(HttpStatusCode.Unauthorized, await Post(client, TelemetryJson.Encode(invalid)));
        var second = await f.Cache.AppendAsync([TestLedger.Event()]);
        Assert.Equal(HttpStatusCode.Conflict, await Post(client, TelemetryJson.Encode(second)));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(client, Encoding.UTF8.GetBytes("{}")));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(client, Encoding.UTF8.GetBytes("not-json")));
        using var content = new ByteArrayContent([1, 2, 3]);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Headers.ContentEncoding.Add("gzip");
        using var response = await client.PostAsync("api/v1/telemetry/blocks", content);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.Null(await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId));
    }
    [Fact]
    public async Task HttpRejectsOversizedChunkedEnvelopesBeforeJsonParsing()
    {
        await using var f = await IngestionFixture.CreateAsync();
        await using var host = await NetworkIngestionHost.StartAsync(f.Service);
        using var client = host.Client();
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/telemetry/blocks")
        { Content = new StreamContent(new MemoryStream(new byte[TelemetryJson.MaximumBlockBytes + 1])) };
        request.Headers.TransferEncodingChunked = true;
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Null(await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId));
    }
    [Fact]
    public async Task GrpcMapsRejectionsAndBoundsPayloadBeforeIssuingAReceipt()
    {
        await using var f = await IngestionFixture.CreateAsync();
        await using var host = await NetworkIngestionHost.StartAsync(f.Service);
        using var http = host.Client();
        using var channel = GrpcChannel.ForAddress(host.GrpcAddress, new GrpcChannelOptions { HttpClient = http });
        var client = new TelemetryIngestion.TelemetryIngestionClient(channel);
        var invalid = TelemetryGrpcCodec.ToProto(f.First); invalid.BlockHash = new string('A', 64);
        using (var call = client.SubmitAsync(invalid))
            Assert.Equal(StatusCode.Unauthenticated, (await Assert.ThrowsAsync<RpcException>(() => call.ResponseAsync)).StatusCode);
        var second = await f.Cache.AppendAsync([TestLedger.Event()]);
        using (var call = client.SubmitAsync(TelemetryGrpcCodec.ToProto(second)))
            Assert.Equal(StatusCode.FailedPrecondition, (await Assert.ThrowsAsync<RpcException>(() => call.ResponseAsync)).StatusCode);
        invalid = TelemetryGrpcCodec.ToProto(f.First); invalid.Payload = Google.Protobuf.ByteString.CopyFrom(new byte[4 * 1024 * 1024 + 1]);
        using (var call = client.SubmitAsync(invalid))
            Assert.Equal(StatusCode.ResourceExhausted, (await Assert.ThrowsAsync<RpcException>(() => call.ResponseAsync)).StatusCode);
        Assert.Null(await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId));
    }
    [Fact]
    public async Task GrpcStreamingTimeoutResetsTheCallAndNextAttemptCanSucceed()
    {
        await using var f = await IngestionFixture.CreateAsync();
        int attempts = 0;
        var delayed = new DelegateIngestor(async (block, token) =>
        {
            if (Interlocked.Increment(ref attempts) == 1) await Task.Delay(Timeout.Infinite, token);
            return await f.Service.IngestAsync(block, token);
        });
        await using var host = await NetworkIngestionHost.StartAsync(delayed);
        using var http = host.Client();
        await using var grpc = new GrpcTelemetryTransport(host.GrpcAddress, f.Local.Server, new() { AllowInsecureLoopback = true, RequestTimeout = TimeSpan.FromSeconds(1) }, httpClient: http);
        var dispatcher = new TelemetryDispatcher(f.Cache, grpc);
        Assert.True((await Assert.ThrowsAsync<TelemetryTransportException>(() => dispatcher.DispatchPendingAsync())).IsTransient);
        Assert.Single(await f.Cache.ReadPendingAsync());
        Assert.Equal(1, await dispatcher.DispatchPendingAsync());
        Assert.Empty(await f.Cache.ReadPendingAsync());
    }

    [Theory]
    [InlineData("http://127.0.0.1:1234", false)]
    [InlineData("http://example.com:1234", true)]
    [InlineData("https://user:secret@example.com", false)]
    public void UnsafeServiceAddressesAreRejected(string address, bool allowLoopback)
    {
        using var fixture = new TestLedger();
        var options = new TelemetryTransportOptions { AllowInsecureLoopback = allowLoopback };
        Assert.Throws<ArgumentException>(() => new HttpTelemetryTransport(new Uri(address), fixture.Server, options));
        Assert.Throws<ArgumentException>(() => new GrpcTelemetryTransport(new Uri(address), fixture.Server, options));
    }
    private static async Task<HttpStatusCode> Post(HttpClient client, byte[] data)
    {
        using var body = new ByteArrayContent(data); body.Headers.ContentType = new("application/json");
        using var response = await client.PostAsync("api/v1/telemetry/blocks", body); return response.StatusCode;
    }
    private sealed class LostReplyTransport(ITelemetryTransport inner) : ITelemetryTransport
    {
        public async Task<SettlementReceipt> SubmitAsync(SignedTelemetryBlock block, CancellationToken cancellationToken = default)
        {
            await inner.SubmitAsync(block, cancellationToken);
            throw new TelemetryTransportException("Simulated response loss after the real receiver committed.", true);
        }
    }
}
