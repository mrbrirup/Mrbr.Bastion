using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.Security;
using Mrbr.Bastion.Operators.AspNetCore;

namespace Mrbr.Bastion.Dashboard;

internal sealed class OperatorAccountEndpoint;
internal sealed record CreateOperatorRequest([property: JsonRequired] string UserName, [property: JsonRequired] string DisplayName, [property: JsonRequired] OperatorRole[] Roles, [property: JsonRequired] string Password);
internal sealed record UpdateOperatorRequest([property: JsonRequired] long Revision, [property: JsonRequired] string DisplayName, [property: JsonRequired] OperatorRole[] Roles, [property: JsonRequired] bool Enabled);
internal sealed record ResetOperatorRequest([property: JsonRequired] long Revision, [property: JsonRequired] string Password);
internal sealed record RevokeOperatorRequest([property: JsonRequired] long Revision);
internal sealed record ChangeOperatorPassword([property: JsonRequired] string CurrentPassword, [property: JsonRequired] string NewPassword);
internal static class OperatorEndpoints
{
    private static IResult Reply<T>(T data) => Results.Json(data, OperatorValidation.Json);
    private static async Task<T> Body<T>(HttpContext c)
    {
        if (!string.Equals(c.Request.ContentType?.Split(';')[0].Trim(), "application/json", StringComparison.OrdinalIgnoreCase)) throw new BadHttpRequestException("JSON required.", 415);
        try { return await JsonSerializer.DeserializeAsync<T>(c.Request.Body, OperatorValidation.Json, c.RequestAborted) ?? throw new ArgumentException("Missing request."); }
        catch (JsonException) { throw new ArgumentException("Invalid operator request."); }
    }
    internal static void Map(RouteGroupBuilder api)
    {
        api.MapPost("/account/password", async (HttpContext c, IAntiforgery csrf) =>
        {
            var accounts = c.RequestServices.GetService<OperatorAccounts>(); if (accounts is null) return Results.Conflict(new { error = "PerUserAuthenticationRequired" });
            await csrf.ValidateRequestAsync(c); var request = await Body<ChangeOperatorPassword>(c);
            if (request.CurrentPassword is null || request.NewPassword is null) throw new ArgumentException("Missing password.");
            if (!await accounts.ChangePasswordAsync(OperatorAuthentication.ActorIdentity(c.User), request.CurrentPassword, request.NewPassword, c.RequestAborted)) return Results.BadRequest(new { error = "CurrentPasswordNotAccepted" });
            await c.SignOutAsync(OperatorAuthentication.Scheme); return Reply(new { signInRequired = true });
        }).WithMetadata(new OperatorAccountEndpoint()).RequireRateLimiting("BastionDashboardLogin");
        var admin = api.MapGroup("/operators").RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.ManageUsers));
        admin.MapGet("", async (string? after, int? limit, [FromServices] IOperatorStore store, CancellationToken ct) => Reply(await store.ReadUsersAsync(after, limit ?? 50, ct)));
        admin.MapPost("", async (HttpContext c, IAntiforgery csrf, [FromServices] OperatorAccounts accounts) =>
        { await csrf.ValidateRequestAsync(c); var request = await Body<CreateOperatorRequest>(c); return Reply(await accounts.CreateAsync(request.UserName, request.DisplayName, request.Roles, request.Password, OperatorAuthentication.ActorIdentity(c.User), ct: c.RequestAborted)); });
        admin.MapPost("/{id:guid}", async (Guid id, HttpContext c, IAntiforgery csrf, [FromServices] IOperatorStore store, TimeProvider clock) =>
        { await csrf.ValidateRequestAsync(c); var request = await Body<UpdateOperatorRequest>(c); return Reply(await store.UpdateAsync(id, request.Revision, request.DisplayName, request.Roles, request.Enabled, OperatorAuthentication.ActorIdentity(c.User), clock.GetUtcNow(), c.RequestAborted)); });
        admin.MapPost("/{id:guid}/password", async (Guid id, HttpContext c, IAntiforgery csrf, [FromServices] OperatorAccounts accounts) =>
        { await csrf.ValidateRequestAsync(c); var request = await Body<ResetOperatorRequest>(c); await accounts.ResetPasswordAsync(id, request.Revision, request.Password, OperatorAuthentication.ActorIdentity(c.User), c.RequestAborted); return Reply(new { updated = true }); });
        admin.MapPost("/{id:guid}/sessions/revoke", async (Guid id, HttpContext c, IAntiforgery csrf, [FromServices] IOperatorStore store, TimeProvider clock) =>
        { await csrf.ValidateRequestAsync(c); var request = await Body<RevokeOperatorRequest>(c); await store.RevokeAllAsync(id, request.Revision, OperatorAuthentication.ActorIdentity(c.User), clock.GetUtcNow(), c.RequestAborted); return Reply(new { revoked = true }); });
        api.MapGet("/operator-security", async (long? before, int? limit, [FromServices] IOperatorStore store, CancellationToken ct) => Reply(await store.ReadSecurityAsync(before, limit ?? 50, ct))).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.SecurityHistory));
    }
}
