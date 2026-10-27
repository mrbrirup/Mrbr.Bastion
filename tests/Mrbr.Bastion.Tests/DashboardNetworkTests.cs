using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Dashboard;
using Mrbr.Bastion.Operations;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class DashboardNetworkTests
{
    [Fact]
    public async Task DashboardRequiresOperatorAccessAndDoesNotExposeInventoryAnonymously()
    {
        await using var f = await OperationsFixture.CreateAsync(); await using var host = await DashboardTestHost.StartAsync(f);
        using var client = host.Client();
        Assert.Equal(HttpStatusCode.Redirect, (await client.GetAsync("/dashboard")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/dashboard/api/fleet")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/dashboard/api/alerts")).StatusCode);
        var page = await client.GetAsync("/dashboard/login"); Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("frame-ancestors 'none'", page.Headers.GetValues("Content-Security-Policy").Single());
        Assert.True(page.Headers.CacheControl!.NoStore);
        string token = DashboardTestHost.FormToken(await page.Content.ReadAsStringAsync());
        var invalid = await client.PostAsync("/dashboard/login", new FormUrlEncodedContent(new Dictionary<string,string>
        { ["accessToken"] = new('x', 32), ["__RequestVerificationToken"] = token }));
        Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("/dashboard/login", new FormUrlEncodedContent(new Dictionary<string,string> { ["accessToken"] = DashboardTestHost.Token }))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/dashboard/api/fleet")).StatusCode);
    }
    [Fact]
    public async Task AuthenticatedFleetHistoryAndEvidenceReadsPreserveSignedHeartbeatAcceptanceTime()
    {
        await using var f = await OperationsFixture.CreateAsync(); await f.Audits.AuditAsync();
        await using var host = await DashboardTestHost.StartAsync(f); using var client = host.Client(); await DashboardTestHost.LoginAsync(client);
        Assert.Contains("Server health", await client.GetStringAsync("/dashboard")); Assert.Contains("Server health", await client.GetStringAsync("/dashboard/"));
        var fleet = await client.GetFromJsonAsync<FleetPage>("/dashboard/api/fleet", DashboardTestHost.Json);
        Assert.Equal(1, fleet!.Summary.Healthy); Assert.Equal(100, fleet.Servers[0].Health!.Assessment.Score);
        var original = fleet.Servers[0].Health!.LastAcceptedAuditUtc;
        string scope = DashboardTestHost.Scope(f.NodeId, f.LedgerId);
        using var history = JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/history?" + scope));
        Assert.Equal(1, history.RootElement.GetProperty("records").GetArrayLength());
        Assert.Equal(1, history.RootElement.GetProperty("records")[0].GetProperty("sequence").GetInt64());
        var audit = await client.GetFromJsonAsync<AuditRecord>("/dashboard/api/audit?" + scope + "&sequence=1", DashboardTestHost.Json);
        Assert.True(AuditProtocol.Verify(audit!.Result, f.Audits.Ledger.Local.Server));
        var server = await client.GetFromJsonAsync<ServerOverview>("/dashboard/api/server?" + scope, DashboardTestHost.Json);
        Assert.Equal(original, server!.Health!.LastAcceptedAuditUtc);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/dashboard/api/server?nodeId=unknown&ledgerId=" + f.LedgerId)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/dashboard/api/audit?" + scope + "&sequence=2")).StatusCode);
    }
    [Fact]
    public async Task AcknowledgementsRequireCsrfAndAreDurableIdempotentOperatorActions()
    {
        await using var f = await OperationsFixture.CreateAsync(); f.Audits.Metrics = f.Audits.Metrics with { State = MonitorState.Stopped }; await f.Audits.AuditAsync();
        await using var host = await DashboardTestHost.StartAsync(f); using var client = host.Client(); await DashboardTestHost.LoginAsync(client);
        await host.Evaluator.EvaluateAsync();
        var alerts = await client.GetFromJsonAsync<AlertPage>("/dashboard/api/alerts", DashboardTestHost.Json); var alert = Assert.Single(alerts!.Alerts);
        Assert.Equal("CollectorStopped", alert.Code);
        string path = "/dashboard/api/alerts/" + alert.Id + "/acknowledge";
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync(path, null)).StatusCode);
        var session = JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/session"));
        string csrf = session.RootElement.GetProperty("csrfToken").GetString()!;
        async Task<ServerAlert?> Ack()
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path); request.Headers.Add("X-CSRF-TOKEN", csrf);
            using var response = await client.SendAsync(request); response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<ServerAlert>(DashboardTestHost.Json);
        }
        var first = await Ack(); Assert.Equal(AlertState.Acknowledged, first!.State); Assert.Equal("operator", first.AcknowledgedBy);
        Assert.Equal(first, await Ack()); await host.Evaluator.EvaluateAsync();
        Assert.Equal(1, (await f.Alerts.CountAsync()).Acknowledged); Assert.Equal(2, (await f.Alerts.ReadEventsAsync(alert.Id)).Length);
        var events = await client.GetFromJsonAsync<AlertEvent[]>("/dashboard/api/alerts/" + alert.Id + "/events", DashboardTestHost.Json); Assert.Equal(2, events!.Length);
        using var logout = new HttpRequestMessage(HttpMethod.Post, "/dashboard/logout"); logout.Headers.Add("X-CSRF-TOKEN", csrf);
        Assert.Equal(HttpStatusCode.Redirect, (await client.SendAsync(logout)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/dashboard/api/fleet")).StatusCode);
    }
    [Fact]
    public async Task DashboardRequiresTlsUnlessLoopbackTestModeIsExplicitlyEnabled()
    {
        await using var f = await OperationsFixture.CreateAsync(); await using var host = await DashboardTestHost.StartAsync(f, allowInsecure: false);
        using var client = host.Client(); Assert.Equal(HttpStatusCode.UpgradeRequired, (await client.GetAsync("/dashboard/login")).StatusCode);
        Assert.Equal(HttpStatusCode.UpgradeRequired, (await client.GetAsync("/dashboard/assets/dashboard.js")).StatusCode);
    }
    [Fact]
    public async Task DashboardQueriesAreBoundedAndMalformedFiltersAreRejected()
    {
        await using var f = await OperationsFixture.CreateAsync(); await using var host = await DashboardTestHost.StartAsync(f); using var client = host.Client(); await DashboardTestHost.LoginAsync(client);
        string scope = DashboardTestHost.Scope(f.NodeId, f.LedgerId);
        foreach (string query in new[] { "/fleet?pageSize=101", "/fleet?state=Compromised", "/fleet?page=-1", "/history?" + scope + "&limit=101", "/history?" + scope + "&beforeSequence=0", "/alerts?state=Invalid", "/alerts?nodeId=missing", "/alerts?limit=101" })
            Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/dashboard/api" + query)).StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await client.PostAsync("/dashboard/login", new StringContent(new string('x', 9000)))).StatusCode);
    }
    [Fact]
    public async Task VerificationFailureIsVisibleAndHistoryFailureDoesNotReturnAHealthyPlaceholder()
    {
        await using var f = await OperationsFixture.CreateAsync(); await f.Audits.AuditAsync();
        await using var host = await DashboardTestHost.StartAsync(f); using var client = host.Client(); await DashboardTestHost.LoginAsync(client);
        f.Reader.Fail = true; await host.Evaluator.EvaluateAsync();
        var fleet = await client.GetFromJsonAsync<FleetPage>("/dashboard/api/fleet", DashboardTestHost.Json);
        Assert.Equal(1, fleet!.Summary.VerificationUnavailable); Assert.Null(fleet.Servers[0].Health);
        var alerts = await client.GetFromJsonAsync<AlertPage>("/dashboard/api/alerts", DashboardTestHost.Json);
        Assert.Contains(alerts!.Alerts, a => a.Code == HealthAlertPolicy.VerificationUnavailable);
        await f.Audits.Store.DisposeAsync();
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.GetAsync("/dashboard/api/history?" + DashboardTestHost.Scope(f.NodeId, f.LedgerId))).StatusCode);
    }
    [Fact]
    public async Task LoginAttemptsAreRateLimitedAndOperatorTokenCannotBeUsedAsBearerCredentials()
    {
        await using var f = await OperationsFixture.CreateAsync(); await using var host = await DashboardTestHost.StartAsync(f); using var client = host.Client();
        using var bearer = new HttpRequestMessage(HttpMethod.Get, "/dashboard/api/fleet"); bearer.Headers.Authorization = new("Bearer", DashboardTestHost.Token);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(bearer)).StatusCode);
        string token = DashboardTestHost.FormToken(await client.GetStringAsync("/dashboard/login"));
        for (int i = 0; i < 10; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/dashboard/login", new FormUrlEncodedContent(new Dictionary<string,string> { ["accessToken"] = "wrong", ["__RequestVerificationToken"] = token }))).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.PostAsync("/dashboard/login", new StringContent(""))).StatusCode);
    }
    [Fact]
    public async Task OperatorSessionCannotBeReusedAfterTheApplicationRestarts()
    {
        await using var f = await OperationsFixture.CreateAsync(); string cookie;
        await using (var first = await DashboardTestHost.StartAsync(f))
        {
            using var client = first.Client();
            string csrf = DashboardTestHost.FormToken(await client.GetStringAsync("/dashboard/login"));
            using var result = await client.PostAsync("/dashboard/login", new FormUrlEncodedContent(new Dictionary<string,string>
            { ["accessToken"] = DashboardTestHost.Token, ["__RequestVerificationToken"] = csrf }));
            cookie = result.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("Mrbr.Bastion.Operator=", StringComparison.Ordinal)).Split(';')[0];
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/dashboard/api/fleet")).StatusCode);
        }
        await using var second = await DashboardTestHost.StartAsync(f); using var afterRestart = second.Client();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/dashboard/api/fleet"); request.Headers.Add("Cookie", cookie);
        Assert.Equal(HttpStatusCode.Unauthorized, (await afterRestart.SendAsync(request)).StatusCode);
    }
    [Fact]
    public async Task EvidenceEndpointPreservesFullWidthSignedCountersForDownload()
    {
        await using var f = await OperationsFixture.CreateAsync(); f.Audits.Metrics = f.Audits.Metrics with { ReceivedEvents = long.MaxValue };
        await f.Audits.AuditAsync(); await using var host = await DashboardTestHost.StartAsync(f); using var client = host.Client(); await DashboardTestHost.LoginAsync(client);
        string document = await client.GetStringAsync("/dashboard/api/audit?" + DashboardTestHost.Scope(f.NodeId, f.LedgerId) + "&sequence=1");
        Assert.Contains(long.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture), document);
        var evidence = JsonSerializer.Deserialize<AuditRecord>(document, DashboardTestHost.Json)!;
        Assert.Equal(long.MaxValue, evidence.Response.Content.Collector.ReceivedEvents);
        Assert.True(AuditProtocol.Verify(evidence.Response, f.Audits.Ledger.Local.Node));
    }
    [Fact]
    public void EnablingDashboardWithoutAStrongOperatorTokenFailsConfiguration()
    {
        var services = new ServiceCollection(); Assert.Throws<ArgumentException>(() => services.AddBastionDashboard(new() { AccessToken = "" }));
        Assert.Throws<ArgumentException>(() => services.AddBastionDashboard(new() { AccessToken = "short" }));
    }
}

internal sealed class DashboardTestHost(WebApplication app, Uri address) : IAsyncDisposable
{
    public const string Token = "test-only-dashboard-operator-token-32-chars";
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    public Uri Address => address;
    public AlertEvaluator Evaluator => app.Services.GetRequiredService<AlertEvaluator>();
    public HttpClient Client() => new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true }) { BaseAddress = Address };
    public static string FormToken(string html) => WebUtility.HtmlDecode(Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]+)\"").Groups[1].Value);
    public static string Scope(string nodeId, Guid ledgerId) => "nodeId=" + Uri.EscapeDataString(nodeId) + "&ledgerId=" + ledgerId;
    public static async Task LoginAsync(HttpClient client)
    {
        string csrf = FormToken(await client.GetStringAsync("/dashboard/login")); Assert.NotEmpty(csrf);
        using var result = await client.PostAsync("/dashboard/login", new FormUrlEncodedContent(new Dictionary<string,string> { ["accessToken"] = Token, ["__RequestVerificationToken"] = csrf }));
        Assert.Equal(HttpStatusCode.Redirect, result.StatusCode);
        Assert.Contains(result.Headers.GetValues("Set-Cookie"), c => c.Contains("httponly", StringComparison.OrdinalIgnoreCase) && c.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase));
    }
    public static async Task<DashboardTestHost> StartAsync(OperationsFixture fixture, bool allowInsecure = true, Action<IServiceCollection>? configure = null,Mrbr.Bastion.Dashboard.DashboardOptions? dashboardOptions=null)
    {
        var builder = WebApplication.CreateSlimBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0, l => l.Protocols = HttpProtocols.Http1));
        builder.Services.AddSingleton(fixture.Inventory); builder.Services.AddSingleton<INodeHealthReader>(fixture.Reader);
        builder.Services.AddSingleton<IAuditHistoryReader>(fixture.Audits.Store); builder.Services.AddSingleton<IAlertStore>(fixture.Alerts);
        builder.Services.AddBastionDashboard(dashboardOptions??new() { AuthenticationMode=Mrbr.Bastion.Operators.AspNetCore.OperatorAuthenticationMode.LegacyToken, AccessToken = Token, AllowInsecureLoopback = allowInsecure });
        configure?.Invoke(builder.Services);
        var app = builder.Build(); app.UseRateLimiter(); app.UseBastionDashboard(); app.MapBastionDashboard();
        try
        {
            await app.StartAsync(); string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            return new(app, new Uri(address));
        }
        catch { await app.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync() { await app.StopAsync(); await app.DisposeAsync(); }
}
