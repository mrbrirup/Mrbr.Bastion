using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Mrbr.Bastion.Operators.AspNetCore;

public enum OperatorAuthenticationMode { Users, LegacyToken }
public sealed record OperatorAuthenticationOptions
{
    public OperatorAuthenticationMode Mode{get;init;}
    public string? LegacyAccessToken{get;init;}
    public bool AllowInsecureLoopback{get;init;}
    public int SessionMinutes{get;init;}=480;
    public void Validate()
    {
        if(!Enum.IsDefined(Mode)||SessionMinutes is <5 or >1440)throw new ArgumentException("Invalid operator authentication options.");
        if(Mode==OperatorAuthenticationMode.LegacyToken&&(string.IsNullOrWhiteSpace(LegacyAccessToken)||LegacyAccessToken.Length is <32 or >256))throw new ArgumentException("Legacy dashboard access requires an explicit secret token of 32 to 256 characters.");
        if(Mode==OperatorAuthenticationMode.Users&&LegacyAccessToken is not null)throw new ArgumentException("Remove Dashboard:AccessToken for per-user authentication, or explicitly select AuthenticationMode=LegacyToken while migrating.");
    }
}
public sealed class LegacyOperatorCredential(string token)
{
    private readonly byte[] _digest=SHA256.HashData(Encoding.UTF8.GetBytes(token));
    public bool Matches(string supplied)=>supplied.Length<=256&&CryptographicOperations.FixedTimeEquals(_digest,SHA256.HashData(Encoding.UTF8.GetBytes(supplied)));
}
public static class OperatorAuthentication
{
    public const string Scheme="BastionOperator",Authenticated="BastionAuthenticated",Read="BastionDashboard",SessionClaim="bastion:session",StampClaim="bastion:stamp",PermissionClaim="bastion:permission",ChangeClaim="bastion:change-password",LegacyClaim="bastion:legacy";
    private const string Unavailable="BastionIdentityUnavailable";
    public static string Policy(string permission)=>"BastionPermission:"+permission;
    public static IServiceCollection AddBastionOperatorAuthentication(this IServiceCollection services,OperatorAuthenticationOptions options)
    {
        options.Validate();services.AddSingleton(options);services.TryAddSingleton(TimeProvider.System);
        if(options.Mode==OperatorAuthenticationMode.LegacyToken)services.AddSingleton(new LegacyOperatorCredential(options.LegacyAccessToken!));
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddAuthentication(Scheme).AddCookie(Scheme,cookie=>
        {
            cookie.Cookie.Name="Mrbr.Bastion.Operator";cookie.Cookie.HttpOnly=true;cookie.Cookie.SameSite=SameSiteMode.Strict;cookie.Cookie.Path="/dashboard";
            cookie.Cookie.SecurePolicy=options.AllowInsecureLoopback?CookieSecurePolicy.SameAsRequest:CookieSecurePolicy.Always;
            cookie.ExpireTimeSpan=TimeSpan.FromMinutes(options.SessionMinutes);cookie.SlidingExpiration=false;cookie.LoginPath="/dashboard/login";
            cookie.Events.OnRedirectToLogin=c=>{if(c.Request.Path.StartsWithSegments("/dashboard/api"))c.Response.StatusCode=401;else c.Response.Redirect("/dashboard/login");return Task.CompletedTask;};
            cookie.Events.OnRedirectToAccessDenied=c=>{c.Response.StatusCode=403;return Task.CompletedTask;};
            cookie.Events.OnValidatePrincipal=async c=>
            {
                if(options.Mode==OperatorAuthenticationMode.LegacyToken)
                {if(c.Principal?.FindFirstValue(LegacyClaim)!="true")c.RejectPrincipal();return;}
                if(!Guid.TryParse(c.Principal?.FindFirstValue(ClaimTypes.NameIdentifier),out var user)||!Guid.TryParse(c.Principal?.FindFirstValue(SessionClaim),out var session)||!Guid.TryParse(c.Principal?.FindFirstValue(StampClaim),out var stamp)){c.RejectPrincipal();return;}
                try
                {
                    var current=await c.HttpContext.RequestServices.GetRequiredService<IOperatorStore>().ReadSessionAsync(session,user,stamp,c.HttpContext.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow(),c.HttpContext.RequestAborted);
                    if(current is null){c.RejectPrincipal();await c.HttpContext.SignOutAsync(Scheme);}else c.ReplacePrincipal(Principal(current));
                }
                catch(OperationCanceledException)when(c.HttpContext.RequestAborted.IsCancellationRequested){throw;}
                catch(Exception error){c.RejectPrincipal();c.HttpContext.Items[Unavailable]=true;c.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Mrbr.Bastion.Operators").LogError(error,"Operator identity validation is unavailable.");}
            };
        });
        services.AddAuthorization(o=>
        {
            o.AddPolicy(Authenticated,p=>p.AddAuthenticationSchemes(Scheme).RequireAuthenticatedUser());
            o.AddPolicy(Read,p=>p.AddAuthenticationSchemes(Scheme).RequireAuthenticatedUser().RequireClaim(PermissionClaim,OperatorPermissions.Read));
            foreach(string permission in OperatorPermissions.All)o.AddPolicy(Policy(permission),p=>p.AddAuthenticationSchemes(Scheme).RequireAuthenticatedUser().RequireClaim(PermissionClaim,permission));
        });return services;
    }
    public static IApplicationBuilder UseBastionOperatorAuthentication(this IApplicationBuilder app)=>app.UseAuthentication().Use(async(c,next)=>
    {if(c.Items.ContainsKey(Unavailable)){c.Response.StatusCode=503;c.Response.Headers.CacheControl="no-store";await c.Response.WriteAsJsonAsync(new{error="OperatorIdentityUnavailable"},c.RequestAborted);}else await next();}).UseAuthorization();
    public static ClaimsPrincipal Principal(OperatorSession session)
    {
        var a=session.Account;var claims=new List<Claim>{new(ClaimTypes.NameIdentifier,a.Id.ToString("D")),new(ClaimTypes.Name,a.UserName),new("bastion:display",a.DisplayName),new(SessionClaim,session.Id.ToString("D")),new(StampClaim,session.SecurityStamp.ToString("D")),new(ChangeClaim,a.MustChangePassword?"true":"false")};
        claims.AddRange(a.Roles.Select(r=>new Claim(ClaimTypes.Role,r.ToString())));
        if(!a.MustChangePassword)claims.AddRange(OperatorPermissions.ForRoles(a.Roles).Select(p=>new Claim(PermissionClaim,p)));
        return new(new ClaimsIdentity(claims,Scheme));
    }
    public static ClaimsPrincipal LegacyPrincipal()=>new(new ClaimsIdentity(new[]{new Claim(ClaimTypes.Name,"operator"),new Claim(LegacyClaim,"true")}
        .Concat(OperatorPermissions.All.Where(p=>p is not(OperatorPermissions.ManageUsers or OperatorPermissions.SecurityHistory)).Select(p=>new Claim(PermissionClaim,p))),Scheme));
    public static string Actor(ClaimsPrincipal user)=>user.FindFirstValue(LegacyClaim)=="true"?"operator":$"{user.Identity!.Name} ({Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!):D})";
    public static OperatorActor ActorIdentity(ClaimsPrincipal user)=>new(Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!),Guid.Parse(user.FindFirstValue(StampClaim)!));
}
