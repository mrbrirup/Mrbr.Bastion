using global::Grpc.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Grpc;
using Mrbr.Bastion.Grpc.Protocol;

namespace Mrbr.Bastion.Ingestion.AspNetCore;

public sealed class TelemetryGrpcService(ITelemetryIngestor ingestor, IngestionEndpointOptions options,
    ILogger<TelemetryGrpcService> logger) : TelemetryIngestion.TelemetryIngestionBase
{
    public override Task<SignedReceipt> Submit(SignedBlock request, ServerCallContext context) => AcceptAsync(request, context);
    public override async Task Exchange(IAsyncStreamReader<SignedBlock> requestStream, IServerStreamWriter<SignedReceipt> responseStream, ServerCallContext context)
    {
        EnsureSecure(context);
        while (true)
        {
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
            idle.CancelAfter(options.StreamIdleTimeout);
            bool next;
            try { next = await requestStream.MoveNext(idle.Token); }
            catch (OperationCanceledException) when (!context.CancellationToken.IsCancellationRequested)
            { throw new RpcException(new Status(StatusCode.DeadlineExceeded, "The telemetry stream was idle.")); }
            if (!next) return;
            var receipt = await AcceptAsync(requestStream.Current, context);
            using var write = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
            write.CancelAfter(options.StreamIdleTimeout);
            await responseStream.WriteAsync(receipt, write.Token);
        }
    }
    private void EnsureSecure(ServerCallContext context)
    {
        if (!IngestionEndpoints.IsSecure(context.GetHttpContext(), options))
            throw new RpcException(new Status(StatusCode.Unauthenticated, "HTTPS is required."));
    }
    private async Task<SignedReceipt> AcceptAsync(SignedBlock request, ServerCallContext context)
    {
        EnsureSecure(context);
        SignedTelemetryBlock block;
        try { block = TelemetryGrpcCodec.FromProto(request); }
        catch (TelemetryMessageTooLargeException) { throw Reject(IngestionFailure.TooLarge); }
        catch (InvalidDataException) { throw Reject(IngestionFailure.InvalidBlock); }
        try { return TelemetryGrpcCodec.ToProto(await ingestor.IngestAsync(block, context.CancellationToken)); }
        catch (TelemetryRejectedException error) { throw Reject(error.Failure); }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error)
        {
            logger.LogError(error, "Telemetry ingestion failed before a receipt could be returned.");
            throw new RpcException(new Status(StatusCode.Unavailable, "Telemetry storage or receipt issuance is unavailable."));
        }
    }
    private static RpcException Reject(IngestionFailure failure) => new(new Status(failure switch
    {
        IngestionFailure.UntrustedBlock => StatusCode.Unauthenticated,
        IngestionFailure.SequenceConflict or IngestionFailure.ChainConflict => StatusCode.FailedPrecondition,
        IngestionFailure.TooLarge or IngestionFailure.CapacityExceeded => StatusCode.ResourceExhausted,
        _ => StatusCode.InvalidArgument
    }, failure.ToString()), new Metadata { { "bastion-failure", failure.ToString() } });
}
