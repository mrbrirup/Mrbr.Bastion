using Google.Protobuf;
using global::Grpc.Core;
using global::Grpc.Net.Client;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Grpc.Protocol;

namespace Mrbr.Bastion.Transport.Grpc;

public sealed class GrpcHeartbeatAuditTransport : IHeartbeatAuditTransport, IDisposable
{
    private readonly GrpcChannel _channel;
    private readonly HeartbeatAudits.HeartbeatAuditsClient _client;
    private readonly ISignatureVerifier _verifier;
    private readonly TelemetryTransportOptions _options;
    public GrpcHeartbeatAuditTransport(Uri serviceAddress, ISignatureVerifier serverVerifier,
        TelemetryTransportOptions? options = null, HttpClient? httpClient = null)
    {
        _verifier = serverVerifier ?? throw new ArgumentNullException(nameof(serverVerifier));
        _options = options ?? new(); _options.ValidateAddress(serviceAddress);
        _channel = GrpcChannel.ForAddress(serviceAddress, new GrpcChannelOptions
        { HttpClient = httpClient, MaxSendMessageSize = AuditProtocol.MaximumEnvelopeBytes + 1024, MaxReceiveMessageSize = AuditProtocol.MaximumEnvelopeBytes + 1024 });
        _client = new(_channel);
    }
    public async Task<SignedAuditChallenge> CreateChallengeAsync(SignedAuditRequest request, CancellationToken cancellationToken = default)
    {
        var result = await Send<SignedAuditRequest, SignedAuditChallenge>(request, (d, t) => _client.CreateChallengeAsync(d, cancellationToken: t), cancellationToken).ConfigureAwait(false);
        if (!AuditProtocol.Verify(result, _verifier)) throw Invalid();
        try { AuditProtocol.Bind(result, request); } catch (InvalidDataException error) { throw Invalid(error); }
        return result;
    }
    public async Task<SignedAuditResult> SubmitAsync(SignedAuditResponse response, CancellationToken cancellationToken = default)
    {
        var result = await Send<SignedAuditResponse, SignedAuditResult>(response, (d, t) => _client.SubmitAuditAsync(d, cancellationToken: t), cancellationToken).ConfigureAwait(false);
        if (!AuditProtocol.Verify(result, _verifier)) throw Invalid();
        try { AuditProtocol.Bind(result, response); } catch (InvalidDataException error) { throw Invalid(error); }
        return result;
    }
    public async Task<SignedNodeHealth> GetHealthAsync(SignedHealthQuery query, CancellationToken cancellationToken = default)
    {
        var result = await Send<SignedHealthQuery, SignedNodeHealth>(query, (d, t) => _client.GetNodeHealthAsync(d, cancellationToken: t), cancellationToken).ConfigureAwait(false);
        if (!AuditProtocol.Verify(result, _verifier)) throw Invalid();
        try { AuditProtocol.Bind(result, query); } catch (InvalidDataException error) { throw Invalid(error); }
        return result;
    }
    private async Task<TOut> Send<TIn, TOut>(TIn value, Func<AuditDocument, CancellationToken, AsyncUnaryCall<AuditDocument>> send, CancellationToken cancellationToken)
    {
        byte[] body = TelemetryJson.Encode(value);
        if (body.Length > AuditProtocol.MaximumEnvelopeBytes) throw new TelemetryTransportException("The audit request exceeds its wire limit.", false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(_options.RequestTimeout);
        try
        {
            using var call = send(new() { Document = ByteString.CopyFrom(body) }, timeout.Token);
            var response = await call.ResponseAsync.ConfigureAwait(false);
            return TelemetryJson.Decode<TOut>(response.Document.Span, AuditProtocol.MaximumEnvelopeBytes);
        }
        catch (RpcException error) when (cancellationToken.IsCancellationRequested) { throw new OperationCanceledException("gRPC audit canceled.", error, cancellationToken); }
        catch (RpcException error)
        {
            string? code = error.Trailers.FirstOrDefault(x => x.Key == "bastion-audit-failure")?.Value;
            if (Enum.TryParse<AuditFailure>(code, out var failure) && Enum.IsDefined(failure)) throw new AuditRejectedException(failure, "The receiver rejected the audit: " + failure);
            throw new TelemetryTransportException($"Heartbeat audit returned gRPC {error.StatusCode}.",
                error.StatusCode is StatusCode.Unavailable or StatusCode.Internal or StatusCode.DeadlineExceeded or StatusCode.Cancelled or StatusCode.Aborted, error);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new TelemetryTransportException("gRPC audit timed out.", true); }
        catch (InvalidDataException error) { throw Invalid(error); }
        catch (TelemetryMessageTooLargeException error) { throw Invalid(error); }
    }
    private static TelemetryTransportException Invalid(Exception? error = null) => new("The receiver returned an invalid, mismatched, or oversized signed audit document.", false, error);
    public void Dispose() => _channel.Dispose();
}
