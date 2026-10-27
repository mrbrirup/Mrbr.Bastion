using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Ingestion.AspNetCore;

public sealed record IngestionEndpointOptions
{
    public bool AllowInsecureLoopback { get; init; }
    public int MaximumConcurrentRequests { get; init; } = 32;
    public TimeSpan StreamIdleTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public string[] AdditionalPayloadFormats{get;init;}=[];
}
public static class IngestionEndpoints
{
    private const string Policy = "Mrbr.Bastion.Ingestion";
    public static IServiceCollection AddBastionIngestionEndpoints(this IServiceCollection services, IngestionEndpointOptions? options = null)
    {
        options ??= new();
        if (options.MaximumConcurrentRequests is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.StreamIdleTimeout <= TimeSpan.Zero || options.StreamIdleTimeout > TimeSpan.FromMinutes(5)) throw new ArgumentOutOfRangeException(nameof(options));
        services.AddSingleton(options);
        services.AddGrpc(o =>
        {
            o.MaxReceiveMessageSize = TelemetryJson.MaximumBlockBytes;
            o.MaxSendMessageSize = TelemetryJson.MaximumReceiptBytes;
            o.EnableDetailedErrors = false;
        });
        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.AddConcurrencyLimiter(Policy, limit => { limit.PermitLimit = options.MaximumConcurrentRequests; limit.QueueLimit = 0; limit.QueueProcessingOrder = QueueProcessingOrder.OldestFirst; });
        });
        return services;
    }
    public static IEndpointRouteBuilder MapBastionIngestion(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/v1/telemetry/blocks", AcceptHttpAsync).RequireRateLimiting(Policy);
        endpoints.MapGet("/api/v1/telemetry/capabilities",(HttpContext c,IngestionEndpointOptions options)=>
            IsSecure(c,options)?Results.Json(new{payloadFormats=new[]{LedgerProtocol.PayloadFormat}.Concat(options.AdditionalPayloadFormats).ToArray()}):Results.StatusCode(426)).RequireRateLimiting(Policy);
        endpoints.MapGrpcService<TelemetryGrpcService>().RequireRateLimiting(Policy);
        return endpoints;
    }
    internal static bool IsSecure(HttpContext context, IngestionEndpointOptions options) => context.Request.IsHttps
        || (options.AllowInsecureLoopback && context.Connection.RemoteIpAddress is { } remote && IPAddress.IsLoopback(remote)
            && context.Connection.LocalIpAddress is { } local && IPAddress.IsLoopback(local));

    private static async Task<IResult> AcceptHttpAsync(HttpContext context, ITelemetryIngestor ingestor,
        IngestionEndpointOptions options, ILoggerFactory loggerFactory)
    {
        if (!IsSecure(context, options)) return Results.StatusCode(StatusCodes.Status426UpgradeRequired);
        if (!string.Equals(context.Request.ContentType?.Split(';')[0].Trim(), "application/json", StringComparison.OrdinalIgnoreCase) || context.Request.Headers.ContentEncoding.Count > 0)
            return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
        if (context.Request.ContentLength > TelemetryJson.MaximumBlockBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        SignedTelemetryBlock block;
        try { block = await TelemetryJson.ReadAsync<SignedTelemetryBlock>(context.Request.Body, TelemetryJson.MaximumBlockBytes, context.RequestAborted); }
        catch (TelemetryMessageTooLargeException) { return Results.StatusCode(StatusCodes.Status413PayloadTooLarge); }
        catch (InvalidDataException) { return Results.BadRequest(new { error = "MalformedEnvelope" }); }
        try
        {
            var receipt = await ingestor.IngestAsync(block, context.RequestAborted);
            return Results.Bytes(TelemetryJson.Encode(receipt), "application/json");
        }
        catch (TelemetryRejectedException error)
        {
            int status = error.Failure switch
            {
                IngestionFailure.UntrustedBlock => 401,
                IngestionFailure.TooLarge => 413,
                IngestionFailure.SequenceConflict or IngestionFailure.ChainConflict => 409,
                IngestionFailure.CapacityExceeded => 503,
                _ => 400
            };
            return Results.Json(new { error = error.Failure.ToString() }, statusCode: status);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
        catch (Exception error)
        {
            loggerFactory.CreateLogger("Mrbr.Bastion.Ingestion").LogError(error, "Telemetry ingestion failed before a receipt could be returned.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }
}
