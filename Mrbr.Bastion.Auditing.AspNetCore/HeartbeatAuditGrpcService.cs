using Google.Protobuf;
using global::Grpc.Core;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Grpc.Protocol;
using Microsoft.Extensions.Logging;

namespace Mrbr.Bastion.Auditing.AspNetCore;

public sealed class HeartbeatAuditGrpcService(IHeartbeatAuditService service, AuditEndpointOptions options,
    ILogger<HeartbeatAuditGrpcService> logger) : HeartbeatAudits.HeartbeatAuditsBase
{
    public override Task<AuditDocument> CreateChallenge(AuditDocument request, ServerCallContext context) =>
        Handle<SignedAuditRequest, SignedAuditChallenge>(request, context, service.CreateChallengeAsync);
    public override Task<AuditDocument> SubmitAudit(AuditDocument request, ServerCallContext context) =>
        Handle<SignedAuditResponse, SignedAuditResult>(request, context, service.SubmitAsync);
    public override Task<AuditDocument> GetNodeHealth(AuditDocument request, ServerCallContext context) =>
        Handle<SignedHealthQuery, SignedNodeHealth>(request, context, service.GetHealthAsync);
    private async Task<AuditDocument> Handle<TIn, TOut>(AuditDocument document, ServerCallContext context, Func<TIn, CancellationToken, Task<TOut>> execute)
    {
        if (!AuditEndpoints.IsSecure(context.GetHttpContext(), options)) throw new RpcException(new Status(StatusCode.Unauthenticated, "HTTPS is required."));
        TIn input;
        try { input = TelemetryJson.Decode<TIn>(document.Document.Span, AuditProtocol.MaximumEnvelopeBytes); }
        catch (Exception error) when (error is InvalidDataException or TelemetryMessageTooLargeException)
        { throw Reject(AuditFailure.InvalidEnvelope); }
        try
        {
            byte[] bytes = TelemetryJson.Encode(await execute(input, context.CancellationToken));
            if (bytes.Length > AuditProtocol.MaximumEnvelopeBytes) throw new InvalidDataException("The audit result exceeds its envelope limit.");
            return new() { Document = ByteString.CopyFrom(bytes) };
        }
        catch (AuditRejectedException error) { throw Reject(error.Failure); }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error)
        { logger.LogError(error, "Heartbeat audit verification or persistence is unavailable."); throw new RpcException(new Status(StatusCode.Unavailable, "Audit verification or persistence is unavailable.")); }
    }
    private static RpcException Reject(AuditFailure failure) => new(new Status(failure switch
    {
        AuditFailure.UntrustedIdentity => StatusCode.Unauthenticated,
        AuditFailure.InvalidEnvelope => StatusCode.InvalidArgument,
        AuditFailure.CapacityExceeded or AuditFailure.ChallengeOutstanding => StatusCode.ResourceExhausted,
        _ => StatusCode.FailedPrecondition
    }, failure.ToString()), new Metadata { { "bastion-audit-failure", failure.ToString() } });
}
