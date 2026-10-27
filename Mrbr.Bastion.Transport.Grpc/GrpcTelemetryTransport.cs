using global::Grpc.Core;
using global::Grpc.Net.Client;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Grpc;
using Mrbr.Bastion.Grpc.Protocol;

namespace Mrbr.Bastion.Transport.Grpc;

/// <summary>Reusable HTTP/2 channel with unary or serialized duplex delivery and one receipt per committed block.</summary>
public sealed class GrpcTelemetryTransport : ITelemetryTransport, IAsyncDisposable
{
    private readonly GrpcChannel _channel;
    private readonly TelemetryIngestion.TelemetryIngestionClient _client;
    private readonly ISignatureVerifier _verifier;
    private readonly TelemetryTransportOptions _options;
    private readonly bool _streaming;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private AsyncDuplexStreamingCall<SignedBlock, SignedReceipt>? _stream;
    private bool _disposed;
    public GrpcTelemetryTransport(Uri serviceAddress, ISignatureVerifier receiptVerifier, TelemetryTransportOptions? options = null,
        bool useStreaming = true, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(receiptVerifier);
        _options = options ?? new();
        _options.ValidateAddress(serviceAddress);
        _verifier = receiptVerifier;
        _streaming = useStreaming;
        _channel = GrpcChannel.ForAddress(serviceAddress, new GrpcChannelOptions
        { HttpClient = httpClient, MaxReceiveMessageSize = TelemetryJson.MaximumReceiptBytes, MaxSendMessageSize = TelemetryJson.MaximumBlockBytes });
        _client = new(_channel);
    }
    public async Task<SettlementReceipt> SubmitAsync(SignedTelemetryBlock block, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(block);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_options.RequestTimeout);
            try
            {
                var request = TelemetryGrpcCodec.ToProto(block);
                if (request.CalculateSize() > TelemetryJson.MaximumBlockBytes) throw new TelemetryTransportException("The gRPC block exceeds its wire size limit.", false);
                SignedReceipt response;
                if (_streaming)
                {
                    _stream ??= _client.Exchange();
                    await _stream.RequestStream.WriteAsync(request, timeout.Token).ConfigureAwait(false);
                    if (!await _stream.ResponseStream.MoveNext(timeout.Token).ConfigureAwait(false))
                        throw new TelemetryTransportException("The gRPC stream ended without a settlement receipt.", true);
                    response = _stream.ResponseStream.Current;
                }
                else
                {
                    using var call = _client.SubmitAsync(request, cancellationToken: timeout.Token);
                    response = await call.ResponseAsync.ConfigureAwait(false);
                }
                return ReceiptValidation.Verify(TelemetryGrpcCodec.FromProto(response), block, _verifier);
            }
            catch (RpcException error) when (cancellationToken.IsCancellationRequested)
            { ResetStream(); throw new OperationCanceledException("gRPC delivery was canceled.", error, cancellationToken); }
            catch (RpcException error)
            {
                ResetStream();
                bool transient = error.StatusCode is StatusCode.Unavailable or StatusCode.DeadlineExceeded or StatusCode.Internal or StatusCode.Aborted or StatusCode.Cancelled
                    || error.Trailers.Any(e => e.Key == "bastion-failure" && e.Value == "CapacityExceeded");
                throw new TelemetryTransportException($"Telemetry ingestion returned gRPC {error.StatusCode}.", transient, error);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            { ResetStream(); throw new TelemetryTransportException("gRPC telemetry delivery timed out.", true); }
            catch (InvalidDataException error) { ResetStream(); throw new TelemetryTransportException("The gRPC receipt is malformed.", false, error); }
            catch (TelemetryMessageTooLargeException error) { ResetStream(); throw new TelemetryTransportException("The gRPC receipt is oversized.", false, error); }
            catch { ResetStream(); throw; }
        }
        finally { _gate.Release(); }
    }
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { if (_disposed) return; _disposed = true; ResetStream(); _channel.Dispose(); }
        finally { _gate.Release(); }
    }
    private void ResetStream() { _stream?.Dispose(); _stream = null; }
}
