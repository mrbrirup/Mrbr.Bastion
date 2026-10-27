using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing.Contracts;

namespace Mrbr.Bastion.Auditing.AspNetCore;

public sealed record AuditEndpointOptions
{
    public bool AllowInsecureLoopback { get; init; }
    public int MaximumConcurrentRequests { get; init; } = 16;
}
public static class AuditEndpoints
{
    private const string Policy = "Mrbr.Bastion.Audits";
    public static IServiceCollection AddBastionAuditEndpoints(this IServiceCollection services, AuditEndpointOptions? options = null)
    {
        options ??= new();
        if (options.MaximumConcurrentRequests is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(options));
        services.AddSingleton(options);
        services.AddGrpc().AddServiceOptions<HeartbeatAuditGrpcService>(o =>
        { o.MaxReceiveMessageSize = AuditProtocol.MaximumEnvelopeBytes + 1024; o.MaxSendMessageSize = AuditProtocol.MaximumEnvelopeBytes + 1024; o.EnableDetailedErrors = false; });
        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = 429;
            o.AddConcurrencyLimiter(Policy, limit => { limit.PermitLimit = options.MaximumConcurrentRequests; limit.QueueLimit = 0; limit.QueueProcessingOrder = QueueProcessingOrder.OldestFirst; });
        });
        return services;
    }
    public static IEndpointRouteBuilder MapBastionAudits(this IEndpointRouteBuilder routes)
    {
        routes.MapPost("/api/v1/audits/challenges", Create).RequireRateLimiting(Policy);
        routes.MapPost("/api/v1/audits/responses", Submit).RequireRateLimiting(Policy);
        routes.MapPost("/api/v1/audits/health", Health).RequireRateLimiting(Policy);
        routes.MapGrpcService<HeartbeatAuditGrpcService>().RequireRateLimiting(Policy);
        return routes;
    }
    internal static bool IsSecure(HttpContext c, AuditEndpointOptions options) => c.Request.IsHttps
        || (options.AllowInsecureLoopback && c.Connection.RemoteIpAddress is { } remote && IPAddress.IsLoopback(remote)
            && c.Connection.LocalIpAddress is { } local && IPAddress.IsLoopback(local));
    private static Task<IResult> Create(HttpContext c, IHeartbeatAuditService service, AuditEndpointOptions o, ILoggerFactory log) =>
        Handle<SignedAuditRequest, SignedAuditChallenge>(c, o, log, service.CreateChallengeAsync);
    private static Task<IResult> Submit(HttpContext c, IHeartbeatAuditService service, AuditEndpointOptions o, ILoggerFactory log) =>
        Handle<SignedAuditResponse, SignedAuditResult>(c, o, log, service.SubmitAsync);
    private static Task<IResult> Health(HttpContext c, IHeartbeatAuditService service, AuditEndpointOptions o, ILoggerFactory log) =>
        Handle<SignedHealthQuery, SignedNodeHealth>(c, o, log, service.GetHealthAsync);
    private static async Task<IResult> Handle<TIn, TOut>(HttpContext context, AuditEndpointOptions options, ILoggerFactory log,
        Func<TIn, CancellationToken, Task<TOut>> execute)
    {
        if (!IsSecure(context, options)) return Results.StatusCode(426);
        if (!string.Equals(context.Request.ContentType?.Split(';')[0].Trim(), "application/json", StringComparison.OrdinalIgnoreCase)
            || context.Request.Headers.ContentEncoding.Count > 0) return Results.StatusCode(415);
        if (context.Request.ContentLength > AuditProtocol.MaximumEnvelopeBytes) return Results.StatusCode(413);
        TIn input;
        try { input = await TelemetryJson.ReadAsync<TIn>(context.Request.Body, AuditProtocol.MaximumEnvelopeBytes, context.RequestAborted); }
        catch (TelemetryMessageTooLargeException) { return Results.StatusCode(413); }
        catch (InvalidDataException) { return Results.Json(new AuditError(AuditFailure.InvalidEnvelope), statusCode: 400); }
        try { return Results.Bytes(TelemetryJson.Encode(await execute(input, context.RequestAborted)), "application/json"); }
        catch (AuditRejectedException error)
        {
            int status = error.Failure switch { AuditFailure.UntrustedIdentity => 401, AuditFailure.InvalidEnvelope => 400,
                AuditFailure.ChallengeOutstanding => 429, AuditFailure.CapacityExceeded => 503, _ => 409 };
            return Results.Json(new AuditError(error.Failure), statusCode: status);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
        catch (Exception error)
        { log.CreateLogger("Mrbr.Bastion.Audits").LogError(error, "Heartbeat audit verification or persistence is unavailable."); return Results.StatusCode(503); }
    }
}
