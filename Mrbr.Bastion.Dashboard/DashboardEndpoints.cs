using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Operations;
using Mrbr.Bastion.Operations.Hosting;
using Mrbr.Bastion.Notifications;
using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.Security;
using Mrbr.Bastion.Operators.AspNetCore;

namespace Mrbr.Bastion.Dashboard;

/// <summary>Cookie-authenticated operator UI. Telemetry/node signing credentials are never accepted as operator credentials.</summary>
public static class DashboardEndpoints
{
    private const string Scheme = OperatorAuthentication.Scheme, LoginLimit = "BastionDashboardLogin", ReadLimit = "BastionDashboardRead";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions EvidenceJson = new(Json) { WriteIndented = true };
    public static IServiceCollection AddBastionDashboard(this IServiceCollection services, DashboardOptions options)
    {
        options.Validate(); services.AddSingleton(options);
        services.AddBastionOperatorAuthentication(new(){Mode=options.AuthenticationMode,LegacyAccessToken=options.AccessToken,AllowInsecureLoopback=options.AllowInsecureLoopback,SessionMinutes=options.SessionMinutes});
        services.AddAntiforgery(o =>
        {
            o.HeaderName = "X-CSRF-TOKEN"; o.Cookie.Name = "Mrbr.Bastion.Csrf"; o.Cookie.Path = "/dashboard";
            o.Cookie.HttpOnly = true; o.Cookie.SameSite = SameSiteMode.Strict;
            o.Cookie.SecurePolicy = options.AllowInsecureLoopback ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
        });
        services.Configure<FormOptions>(o => { o.ValueLengthLimit = 1024; o.KeyLengthLimit = 128; o.ValueCountLimit = 8; });
        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = 429;
            o.AddPolicy(LoginLimit,c=>RateLimitPartition.GetFixedWindowLimiter(c.Connection.RemoteIpAddress?.ToString()??"unknown",_=>new(){PermitLimit=10,Window=TimeSpan.FromMinutes(1),QueueLimit=0}));
            o.AddConcurrencyLimiter(ReadLimit, l => { l.PermitLimit = 8; l.QueueLimit = 0; l.QueueProcessingOrder = QueueProcessingOrder.OldestFirst; });
        });
        services.AddBastionOperations(new() { AlertEvaluationIntervalSeconds = options.AlertEvaluationIntervalSeconds });
        services.TryAddSingleton<INotificationMonitor, DisabledNotificationMonitor>();
        return services;
    }
    public static IApplicationBuilder UseBastionDashboard(this IApplicationBuilder app) => app.UseBastionOperatorAuthentication();
    public static IEndpointRouteBuilder MapBastionDashboard(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/dashboard");
        group.AddEndpointFilter(async (invocation, next) =>
        {
            var c = invocation.HttpContext; var options = c.RequestServices.GetRequiredService<DashboardOptions>();
            if (!c.Request.IsHttps && !(options.AllowInsecureLoopback
                && c.Connection.RemoteIpAddress is { } remote && IPAddress.IsLoopback(remote)
                && c.Connection.LocalIpAddress is { } local && IPAddress.IsLoopback(local))) return Results.StatusCode(426);
            c.Response.Headers.CacheControl = "no-cache, no-store"; c.Response.Headers.Pragma = "no-cache"; c.Response.Headers.XContentTypeOptions = "nosniff";
            c.Response.Headers.XFrameOptions = "DENY"; c.Response.Headers["Referrer-Policy"] = "no-referrer";
            c.Response.Headers.ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
            if (c.Request.IsHttps) c.Response.Headers.StrictTransportSecurity = "max-age=86400";
            if (c.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } body) body.MaxRequestBodySize = 8192;
            if (c.Request.ContentLength > 8192) return Results.StatusCode(413);
            try { return await next(invocation); }
            catch (AntiforgeryValidationException) { return Results.BadRequest(new { error = "InvalidCsrfToken" }); }
            catch (KeyNotFoundException) { return Results.NotFound(); }
            catch (NotificationConflictException error) { return Results.Conflict(new { error = error.Code }); }
            catch (OperatorConflictException error) { return Results.Conflict(new{error=error.Code}); }
            catch (OperatorAccessException) { return Results.StatusCode(403); }
            catch (ArgumentException) { return Results.BadRequest(new { error = "InvalidQuery" }); }
            catch (BadHttpRequestException error) { return Results.StatusCode(error.StatusCode); }
            catch (OperationCanceledException) when (c.RequestAborted.IsCancellationRequested) { throw; }
            catch (Exception error)
            {
                c.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Mrbr.Bastion.Dashboard").LogError(error, "An operator dashboard query or action failed.");
                return Results.Json(new { error = "EvidenceOrStorageUnavailable" }, statusCode: 503);
            }
        });
        group.MapGet("/login", (HttpContext c, IAntiforgery csrf) => LoginPage(c, csrf, false));
        group.MapPost("/login", LoginAsync).RequireRateLimiting(LoginLimit);
        group.MapGet("/assets/dashboard.css", () => Asset("dashboard.css", "text/css"));
        group.MapGet("/assets/dashboard.js", () => Asset("dashboard.js", "text/javascript"));
        group.MapGet("", () => Asset("index.html", "text/html")).RequireAuthorization(OperatorAuthentication.Authenticated);
        group.MapPost("/logout", async (HttpContext c, IAntiforgery csrf) =>
        {
            await csrf.ValidateRequestAsync(c);
            if(Guid.TryParse(c.User.FindFirstValue(OperatorAuthentication.SessionClaim),out var session)&&Guid.TryParse(c.User.FindFirstValue(ClaimTypes.NameIdentifier),out var user))
                await c.RequestServices.GetRequiredService<IOperatorStore>().RevokeSessionAsync(session,user,c.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow(),c.RequestAborted);
            await c.SignOutAsync(Scheme); return Results.Redirect("/dashboard/login");
        }).RequireAuthorization(OperatorAuthentication.Authenticated);
        var api = group.MapGroup("/api").RequireAuthorization(OperatorAuthentication.Authenticated).RequireRateLimiting(ReadLimit);
        api.AddEndpointFilter(async(invocation,next)=>
        {
            var endpoint=invocation.HttpContext.GetEndpoint();
            bool account=endpoint?.Metadata.GetMetadata<OperatorAccountEndpoint>() is not null;
            if(!account&&!invocation.HttpContext.User.HasClaim(OperatorAuthentication.PermissionClaim,OperatorPermissions.Read))return Results.StatusCode(403);
            return await next(invocation);
        });
        OperatorEndpoints.Map(api);
        SoftwareEndpoints.Map(api);
        api.MapGet("/session", async (HttpContext c, IAntiforgery csrf, AlertEvaluator evaluator, DashboardOptions options, IAlertStore alerts, INotificationMonitor notifications) =>
        {
            bool read=c.User.HasClaim(OperatorAuthentication.PermissionClaim,OperatorPermissions.Read);
            return Reply(new
        { csrfToken = csrf.GetAndStoreTokens(c).RequestToken, operatorName = c.User.Identity!.Name,displayName=c.User.FindFirstValue("bastion:display")??"Shared operator",userId=c.User.FindFirstValue(ClaimTypes.NameIdentifier),
            roles=c.User.FindAll(ClaimTypes.Role).Select(r=>r.Value).ToArray(),permissions=c.User.FindAll(OperatorAuthentication.PermissionClaim).Select(p=>p.Value).ToArray(),mustChangePassword=c.User.FindFirstValue(OperatorAuthentication.ChangeClaim)=="true",authenticationMode=options.AuthenticationMode.ToString(),alertPolicy = HealthAlertPolicy.Version,
            evaluation = read?evaluator.Status:null, evaluationIntervalSeconds = options.AlertEvaluationIntervalSeconds, alerts = read?await alerts.CountAsync(c.RequestAborted):new AlertCounts(0,0,0), notifications = read?notifications.Status:null,
            notificationCounts = read&&c.RequestServices.GetService<INotificationReader>() is { } notificationReader ? await notificationReader.CountAsync(c.RequestAborted) : new NotificationCounts(0, 0, 0, 0) });
        }).WithMetadata(new OperatorAccountEndpoint());
        api.MapGet("/fleet", async (string? search, string? state, int? page, int? pageSize, OperationsService service, CancellationToken cancellationToken) =>
            Reply(await service.ReadFleetAsync(search, Parse<ServerHealthState>(state), page ?? 1, pageSize ?? 25, cancellationToken)));
        api.MapGet("/server", async (string nodeId, Guid ledgerId, OperationsService service, CancellationToken cancellationToken) =>
            Reply(await service.ReadServerAsync(nodeId, ledgerId, cancellationToken)));
        api.MapGet("/history", async (string nodeId, Guid ledgerId, long? beforeSequence, int? limit, OperationsService service, CancellationToken cancellationToken) =>
        {
            var page = await service.ReadHistoryAsync(nodeId, ledgerId, beforeSequence, limit ?? 25, cancellationToken);
            return Reply(new { records = page.Records.Select(r => new
            {
                sequence = r.Result.Content.AuditSequenceNumber, r.Result.Content.AcceptedUtc, r.Response.Content.SampledUtc,
                r.Response.Content.CollectorRunId, r.Response.Content.CollectorUptimeMilliseconds, r.Response.Content.Collector,
                r.Response.Content.Cache, r.Result.Content.Findings, r.Result.Content.NewQueueDroppedEvents, r.Result.Content.NewSourceLostEvents,
                r.Result.Content.Policy, resultHash = AuditProtocol.Hash(AuditProtocol.Encode(r.Result.Content))
            }), page.NextBeforeSequence });
        });
        api.MapGet("/audit", async (string nodeId, Guid ledgerId, long sequence, OperationsService service, CancellationToken cancellationToken) =>
        {
            if (sequence < 1) return Results.BadRequest();
            var page = await service.ReadHistoryAsync(nodeId, ledgerId, sequence == long.MaxValue ? null : sequence + 1, 1, cancellationToken);
            var record = page.Records.SingleOrDefault(r => r.Result.Content.AuditSequenceNumber == sequence);
            return record is null ? Results.NotFound() : Results.Json(record, EvidenceJson);
        }).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Evidence));
        api.MapGet("/alerts", async (string? nodeId, Guid? ledgerId, string? state, long? beforeId, int? limit,
            OperationsService operations, IAlertStore store, CancellationToken cancellationToken) =>
        {
            if ((nodeId is null) != (ledgerId is null)) return Results.BadRequest();
            if (nodeId is not null) operations.RequireEnrollment(nodeId, ledgerId!.Value);
            bool active = state is null || state.Equals("Active", StringComparison.OrdinalIgnoreCase);
            return Reply(await store.ReadAsync(new(nodeId, ledgerId, active || state == "All" ? null : Parse<AlertState>(state), beforeId, limit ?? 25, active), cancellationToken));
        });
        api.MapGet("/alerts/{id:long}/events", async (long id, IAlertStore store, CancellationToken cancellationToken) => Reply(await store.ReadEventsAsync(id, cancellationToken))).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Evidence));
        api.MapPost("/alerts/{id:long}/acknowledge", async (long id, HttpContext c, IAntiforgery csrf, IAlertStore store) =>
        {
            await csrf.ValidateRequestAsync(c);
            var alert = await store.AcknowledgeAsync(id, OperatorAuthentication.Actor(c.User), DateTimeOffset.UtcNow, c.RequestAborted);
            return alert is null ? Results.NotFound() : Reply(alert);
        }).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Acknowledge));
        api.MapGet("/notifications", async (HttpContext c, string? state, string? routeId, long? beforeSequence, int? limit, long? alertId, INotificationMonitor monitor) =>
        {
            var reader = c.RequestServices.GetService<INotificationReader>();
            var query = new NotificationQuery(Parse<NotificationState>(state), routeId, beforeSequence, limit ?? 25, alertId);
            if (reader is null) return Reply(new { deliveries = Array.Empty<NotificationDelivery>(), nextBeforeSequence = (long?)null, counts = new NotificationCounts(0, 0, 0, 0), worker = monitor.Status });
            var page = await reader.ReadAsync(query, c.RequestAborted);
            return Reply(new { page.Deliveries, page.NextBeforeSequence, counts = await reader.CountAsync(c.RequestAborted), worker = monitor.Status });
        });
        api.MapGet("/notifications/{id:guid}", async (Guid id, HttpContext c) =>
        {
            var reader = c.RequestServices.GetService<INotificationReader>();
            var detail = reader is null ? null : await reader.ReadDetailAsync(id, c.RequestAborted);
            return detail is null ? Results.NotFound() : Reply(detail);
        }).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Evidence));
        api.MapPost("/notifications/{id:guid}/retry", async (Guid id, HttpContext c, IAntiforgery csrf, INotificationMonitor monitor) =>
        {
            await csrf.ValidateRequestAsync(c);
            var queue = c.RequestServices.GetService<INotificationQueue>();
            if (queue is null || !monitor.Status.Enabled) throw new NotificationConflictException("NotificationsDisabled");
            var detail = await queue.ReadDetailAsync(id, c.RequestAborted);
            if (detail is null) return Results.NotFound();
            if (!monitor.Status.ActiveRoutes.Contains(detail.Delivery.RouteId, StringComparer.Ordinal)) throw new NotificationConflictException("NotificationRouteInactive");
            return Reply(await queue.RedriveAsync(id, OperatorAuthentication.Actor(c.User), DateTimeOffset.UtcNow, c.RequestAborted));
        }).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Retry));
        return endpoints;
    }
    private static T? Parse<T>(string? value) where T : struct, Enum => value is null || value.Length == 0 ? null
        : Enum.TryParse<T>(value, true, out var result) && Enum.IsDefined(result) ? result : throw new ArgumentException("Invalid filter.");
    private static IResult Reply<T>(T data) => Results.Json(data, Json);
    private static IResult Asset(string file, string contentType)
    {
        using var stream = typeof(DashboardEndpoints).Assembly.GetManifestResourceStream("Mrbr.Bastion.Dashboard.Assets." + file)
            ?? throw new InvalidOperationException("Dashboard asset is missing.");
        using var reader = new StreamReader(stream); return Results.Content(reader.ReadToEnd(), contentType, Encoding.UTF8);
    }
    private static IResult LoginPage(HttpContext c, IAntiforgery csrf, bool failed)
    {
        string token = HtmlEncoder.Default.Encode(csrf.GetAndStoreTokens(c).RequestToken!);
        bool legacy=c.RequestServices.GetRequiredService<DashboardOptions>().AuthenticationMode==OperatorAuthenticationMode.LegacyToken;
        return Results.Content("""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Operator sign in · Mrbr.Bastion</title><link rel="stylesheet" href="/dashboard/assets/dashboard.css"></head>
            <body class="login-page"><main class="login-card"><div class="brand-mark">B</div><p class="eyebrow">MRBR.BASTION / CENTRAL OPERATIONS</p>
            <h1>Operator access</h1><p class="muted">Sign in to view server health, verified audit history, and alerts.</p>
            <form method="post" action="/dashboard/login">
            """ +(legacy?"""
            <label for="accessToken">Operator access token</label><input id="accessToken" name="accessToken" type="password" autocomplete="current-password" required minlength="32" maxlength="256" autofocus>
            <p class="fineprint">Shared-token migration mode. Actions cannot be attributed to a named user.</p>
            """:"""
            <label for="userName">Username</label><input id="userName" name="userName" autocomplete="username" required maxlength="64" autofocus>
            <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="128">
            """) + $"<input type=\"hidden\" name=\"__RequestVerificationToken\" value=\"{token}\">"
            + (failed ? "<p class=\"error\" role=\"alert\">Sign in was not accepted. Check your credentials or try again later.</p>" : "") + """
            <button class="primary" type="submit">Sign in</button></form><p class="fineprint">Access is restricted to authorized operators. Sessions expire after their configured lifetime or a server restart.</p>
            </main></body></html>
            """, "text/html", Encoding.UTF8, failed ? 401 : 200);
    }
    private static async Task<IResult> LoginAsync(HttpContext c, IAntiforgery csrf, DashboardOptions options)
    {
        if (!c.Request.HasFormContentType) return Results.StatusCode(415);
        await csrf.ValidateRequestAsync(c);
        var form = await c.Request.ReadFormAsync(c.RequestAborted);
        ClaimsPrincipal principal;DateTimeOffset expires;
        if(options.AuthenticationMode==OperatorAuthenticationMode.LegacyToken)
        {
            if(!c.RequestServices.GetRequiredService<LegacyOperatorCredential>().Matches(form["accessToken"].ToString()))return LoginPage(c,csrf,true);
            principal=OperatorAuthentication.LegacyPrincipal();expires=DateTimeOffset.UtcNow.AddMinutes(options.SessionMinutes);
        }
        else
        {
            var session=await c.RequestServices.GetRequiredService<OperatorAccounts>().LoginAsync(form["userName"].ToString(),form["password"].ToString(),c.Connection.RemoteIpAddress?.ToString(),TimeSpan.FromMinutes(options.SessionMinutes),c.RequestAborted);
            if(session is null)return LoginPage(c,csrf,true);principal=OperatorAuthentication.Principal(session);expires=session.ExpiresUtc;
        }
        await c.SignInAsync(Scheme, principal, new AuthenticationProperties { IsPersistent = false, AllowRefresh = false,ExpiresUtc=expires });
        return Results.Redirect("/dashboard");
    }
}
