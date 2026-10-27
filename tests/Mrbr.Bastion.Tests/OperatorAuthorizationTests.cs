using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.AspNetCore;
using Mrbr.Bastion.Vulnerabilities;
using Mrbr.Bastion.Vulnerabilities.Sqlite;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class OperatorAuthorizationTests
{
    [Theory]
    [InlineData(OperatorRole.Viewer,false,false,false)]
    [InlineData(OperatorRole.Operator,true,true,false)]
    [InlineData(OperatorRole.Analyst,true,false,true)]
    [InlineData(OperatorRole.Administrator,true,true,true)]
    public async Task RolePermissionsAreEnforcedAtApiBoundaries(OperatorRole role,bool evidence,bool acknowledge,bool review)
    {
        await using var users=await OperatorFixture.CreateAsync();await using var operations=await OperationsFixture.CreateAsync();var account=await users.CreateUserAsync("test-user",[role]);
        await operations.Audits.AuditAsync();await operations.Alerts.ApplyAsync(new(operations.NodeId,operations.LedgerId,DateTimeOffset.UtcNow,[new("Offline",AlertSeverity.Critical)],true));
        long alert=Assert.Single((await operations.Alerts.ReadAsync(new())).Alerts).Id;await using var host=await users.HostAsync(operations);using var client=host.Client();
        Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/dashboard/api/operators")).StatusCode);await OperatorFixture.LoginClientAsync(client,account.UserName);
        Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/dashboard/api/fleet")).StatusCode);
        Assert.Equal(evidence?HttpStatusCode.OK:HttpStatusCode.Forbidden,(await client.GetAsync("/dashboard/api/audit?"+DashboardTestHost.Scope(operations.NodeId,operations.LedgerId)+"&sequence=1")).StatusCode);
        using var ack=await OperatorFixture.PostAsync(client,"alerts/"+alert+"/acknowledge",new{});Assert.Equal(acknowledge?HttpStatusCode.OK:HttpStatusCode.Forbidden,ack.StatusCode);
        using var mapping=await OperatorFixture.PostAsync(client,"mappings",new{});Assert.Equal(review?HttpStatusCode.Conflict:HttpStatusCode.Forbidden,mapping.StatusCode);
        using var retry=await OperatorFixture.PostAsync(client,"notifications/"+Guid.NewGuid()+"/retry",new{});Assert.Equal(acknowledge?HttpStatusCode.Conflict:HttpStatusCode.Forbidden,retry.StatusCode);
        Assert.Equal(review?HttpStatusCode.Conflict:HttpStatusCode.Forbidden,(await client.GetAsync("/dashboard/api/products?query=widget")).StatusCode);
        Assert.Equal(role==OperatorRole.Administrator?HttpStatusCode.OK:HttpStatusCode.Forbidden,(await client.GetAsync("/dashboard/api/operators")).StatusCode);
        Assert.Equal(role==OperatorRole.Administrator?HttpStatusCode.OK:HttpStatusCode.Forbidden,(await client.GetAsync("/dashboard/api/operator-security")).StatusCode);
        if(acknowledge)Assert.Equal(OperatorValidation.Actor(account),Assert.Single((await operations.Alerts.ReadAsync(new())).Alerts).AcknowledgedBy);
    }
    [Fact]
    public async Task NewAccountsMustChangePasswordBeforeReadingOperationalData()
    {
        await using var users=await OperatorFixture.CreateAsync();await using var operations=await OperationsFixture.CreateAsync();var account=await users.CreateUserAsync("temporary",[OperatorRole.Administrator],mustChange:true);
        await using var host=await users.HostAsync(operations);using var client=host.Client();await OperatorFixture.LoginClientAsync(client,account.UserName);
        using(var session=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/session"))){Assert.True(session.RootElement.GetProperty("mustChangePassword").GetBoolean());Assert.Equal(0,session.RootElement.GetProperty("permissions").GetArrayLength());}
        foreach(string path in new[]{"fleet","alerts","notifications","operators","software?"+DashboardTestHost.Scope(operations.NodeId,operations.LedgerId)})Assert.Equal(HttpStatusCode.Forbidden,(await client.GetAsync("/dashboard/api/"+path)).StatusCode);
        Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/dashboard")).StatusCode);
        using var noCsrf=await OperatorFixture.PostAsync(client,"account/password",new{currentPassword=OperatorFixture.Password,newPassword="new-personal-password-value"},csrf:false);Assert.Equal(HttpStatusCode.BadRequest,noCsrf.StatusCode);
        using var change=await OperatorFixture.PostAsync(client,"account/password",new{currentPassword=OperatorFixture.Password,newPassword="new-personal-password-value"});Assert.Equal(HttpStatusCode.OK,change.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/dashboard/api/session")).StatusCode);
        await OperatorFixture.LoginClientAsync(client,account.UserName,"new-personal-password-value");Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/dashboard/api/operators")).StatusCode);
    }
    [Fact]
    public async Task AdminMutationsRequireCsrfRejectExtraFieldsAndDoNotLeakSecrets()
    {
        await using var users=await OperatorFixture.CreateAsync();await using var operations=await OperationsFixture.CreateAsync();await using var host=await users.HostAsync(operations);using var client=host.Client();await OperatorFixture.LoginClientAsync(client);
        var create=new{userName="viewer",displayName="Read Only User",roles=new[]{"Viewer"},password=OperatorFixture.Password};
        using var noCsrf=await OperatorFixture.PostAsync(client,"operators",create,csrf:false);Assert.Equal(HttpStatusCode.BadRequest,noCsrf.StatusCode);
        using var forged=await OperatorFixture.PostAsync(client,"operators",new{create.userName,create.displayName,create.roles,create.password,securityStamp=Guid.NewGuid()});Assert.Equal(HttpStatusCode.BadRequest,forged.StatusCode);
        using var created=await OperatorFixture.PostAsync(client,"operators",create);created.EnsureSuccessStatusCode();var user=(await created.Content.ReadFromJsonAsync<OperatorAccount>(OperatorValidation.Json))!;Assert.True(user.MustChangePassword);
        string list=await client.GetStringAsync("/dashboard/api/operators");Assert.DoesNotContain("passwordHash",list,StringComparison.OrdinalIgnoreCase);Assert.DoesNotContain("securityStamp",list);Assert.DoesNotContain(OperatorFixture.Password,list);
        using var update=await OperatorFixture.PostAsync(client,"operators/"+user.Id,new{revision=user.Revision,displayName="Changed",roles=new[]{"Viewer"},enabled=false});update.EnsureSuccessStatusCode();
        using var stale=await OperatorFixture.PostAsync(client,"operators/"+user.Id,new{revision=user.Revision,displayName="Stale",roles=new[]{"Administrator"},enabled=true});Assert.Equal(HttpStatusCode.Conflict,stale.StatusCode);
        string history=await client.GetStringAsync("/dashboard/api/operator-security");Assert.Contains("OperatorCreated",history);Assert.DoesNotContain(OperatorFixture.Password,history);Assert.DoesNotContain("passwordHash",history);Assert.DoesNotContain("securityStamp",history);
        Assert.Equal(HttpStatusCode.BadRequest,(await client.GetAsync("/dashboard/api/operators?limit=101")).StatusCode);Assert.Equal(HttpStatusCode.BadRequest,(await client.GetAsync("/dashboard/api/operator-security?before=0")).StatusCode);
    }
    [Fact]
    public async Task DisabledAndDemotedUsersLoseExistingCookiesOnTheNextRequest()
    {
        await using var users=await OperatorFixture.CreateAsync();await using var operations=await OperationsFixture.CreateAsync();var account=await users.CreateUserAsync("oncall",[OperatorRole.Operator]);
        await using var host=await users.HostAsync(operations);using var client=host.Client();await OperatorFixture.LoginClientAsync(client,account.UserName);
        var viewer=await users.Store.UpdateAsync(account.Id,account.Revision,account.DisplayName,[OperatorRole.Viewer],true,users.Actor,users.Clock.GetUtcNow());
        Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/dashboard/api/fleet")).StatusCode);await OperatorFixture.LoginClientAsync(client,account.UserName);
        using var forbidden=await OperatorFixture.PostAsync(client,"alerts/1/acknowledge",new{});Assert.Equal(HttpStatusCode.Forbidden,forbidden.StatusCode);
        await users.Store.UpdateAsync(viewer.Id,viewer.Revision,viewer.DisplayName,viewer.Roles,false,users.Actor,users.Clock.GetUtcNow());Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/dashboard/api/fleet")).StatusCode);
    }
    [Fact]
    public async Task LoggedOutCookiesCannotBeReplayedAndIdentityStoreFailureIsFailClosed()
    {
        await using var users=await OperatorFixture.CreateAsync();await using var operations=await OperationsFixture.CreateAsync();await using var host=await users.HostAsync(operations);using var client=host.Client();
        string csrf=DashboardTestHost.FormToken(await client.GetStringAsync("/dashboard/login"));using var login=await client.PostAsync("/dashboard/login",new FormUrlEncodedContent(new Dictionary<string,string>{{"userName","admin"},{"password",OperatorFixture.Password},{"__RequestVerificationToken",csrf}}));
        string cookie=login.Headers.GetValues("Set-Cookie").Single(h=>h.StartsWith("Mrbr.Bastion.Operator=",StringComparison.Ordinal)).Split(';')[0];
        using var session=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/session"));using var logout=new HttpRequestMessage(HttpMethod.Post,"/dashboard/logout");logout.Headers.Add("X-CSRF-TOKEN",session.RootElement.GetProperty("csrfToken").GetString());Assert.Equal(HttpStatusCode.Redirect,(await client.SendAsync(logout)).StatusCode);
        using var replayClient=new HttpClient(new HttpClientHandler{UseCookies=false,AllowAutoRedirect=false}){BaseAddress=host.Address};using var replay=new HttpRequestMessage(HttpMethod.Get,"/dashboard/api/fleet");replay.Headers.Add("Cookie",cookie);Assert.Equal(HttpStatusCode.Unauthorized,(await replayClient.SendAsync(replay)).StatusCode);
        await OperatorFixture.LoginClientAsync(client);await users.Store.DisposeAsync();Assert.Equal(HttpStatusCode.ServiceUnavailable,(await client.GetAsync("/dashboard/api/fleet")).StatusCode);
    }
    [Fact]
    public async Task AnalystMappingReviewsAreAttributedToTheAuthenticatedIdentity()
    {
        await using var users=await OperatorFixture.CreateAsync();await using var operations=await OperationsFixture.CreateAsync();var analyst=await users.CreateUserAsync("analyst",[OperatorRole.Analyst]);await using var exposures=SqliteExposureStore.Open(Path.Combine(users.Temp.DirectoryPath,"exposure.db"));
        await using var host=await DashboardTestHost.StartAsync(operations,configure:services=>{services.AddSingleton<IOperatorStore>(users.Store);services.AddSingleton(users.Accounts);services.AddSingleton<TimeProvider>(users.Clock);services.AddSingleton<IExposureReader>(exposures);services.AddSingleton<IMappingReviewer>(exposures);},dashboardOptions:new(){AllowInsecureLoopback=true});
        using var client=host.Client();await OperatorFixture.LoginClientAsync(client,analyst.UserName);
        using var response=await OperatorFixture.PostAsync(client,"mappings",new{id="widget",revision=1,publisher="Vendor",product="Widget",cpe=SoftwareEvidence.Cpe,scheme="Numeric",versionField="ProductVersion"});response.EnsureSuccessStatusCode();
        Assert.Equal(OperatorValidation.Actor(analyst),Assert.Single(await exposures.ReadMappingsAsync()).Reviewer);
    }
    [Fact]
    public async Task LegacyCompatibilityIsExplicitAndCannotAdministerNamedUsers()
    {
        Assert.Throws<ArgumentException>(()=>new OperatorAuthenticationOptions{LegacyAccessToken=DashboardTestHost.Token}.Validate());
        await using var operations=await OperationsFixture.CreateAsync();await using var host=await DashboardTestHost.StartAsync(operations);using var client=host.Client();await DashboardTestHost.LoginAsync(client);
        Assert.Equal(HttpStatusCode.Forbidden,(await client.GetAsync("/dashboard/api/operators")).StatusCode);Assert.Equal(HttpStatusCode.Forbidden,(await client.GetAsync("/dashboard/api/operator-security")).StatusCode);
        using var session=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/session"));Assert.Equal("LegacyToken",session.RootElement.GetProperty("authenticationMode").GetString());
    }
}
