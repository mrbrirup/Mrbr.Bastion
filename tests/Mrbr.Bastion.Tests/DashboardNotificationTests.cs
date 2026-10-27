using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Bastion.Notifications;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class DashboardNotificationTests
{
    [Fact]
    public async Task DeliveryQueriesRequireOperatorAccessAndExplainDisabledNotifications()
    {
        await using var f = await OperationsFixture.CreateAsync(); await using var host = await DashboardTestHost.StartAsync(f); using var client = host.Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/dashboard/api/notifications")).StatusCode);
        await DashboardTestHost.LoginAsync(client);
        using var page = JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/notifications"));
        Assert.False(page.RootElement.GetProperty("worker").GetProperty("enabled").GetBoolean());
        Assert.Equal(0, page.RootElement.GetProperty("deliveries").GetArrayLength());
    }
    [Fact]
    public async Task OperatorCanInspectAttemptsAndRetryADeadLetterOnlyWithCsrf()
    {
        await using var f = await NotificationFixture.CreateAsync(); f.Clock.SetUtc(DateTimeOffset.UtcNow.AddMinutes(-1));
        f.Transport.OnSend = (_, _) => Task.FromResult(NotificationResult.Permanent("HttpPermanentFailure", 401));
        await f.ObserveAsync("Offline"); await f.Dispatcher.RunOnceAsync(); var job = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries);
        await using var host = await DashboardTestHost.StartAsync(f.Operations, configure: services => Register(services, f));
        using var client = host.Client(); await DashboardTestHost.LoginAsync(client);
        using var page = JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/notifications?state=DeadLetter"));
        Assert.Equal(1, page.RootElement.GetProperty("deliveries").GetArrayLength()); Assert.Equal(1, page.RootElement.GetProperty("counts").GetProperty("deadLetter").GetInt32());
        var detail = await client.GetFromJsonAsync<NotificationDetail>("/dashboard/api/notifications/" + job.Id, DashboardTestHost.Json);
        Assert.Equal(401, Assert.Single(detail!.Attempts).RemoteStatus);
        string endpoint = "/dashboard/api/notifications/" + job.Id + "/retry";
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync(endpoint, null)).StatusCode);
        using var session = JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/session")); string csrf = session.RootElement.GetProperty("csrfToken").GetString()!;
        async Task<HttpResponseMessage> Retry()
        { using var request = new HttpRequestMessage(HttpMethod.Post, endpoint); request.Headers.Add("X-CSRF-TOKEN", csrf); return await client.SendAsync(request); }
        using var first = await Retry(); first.EnsureSuccessStatusCode(); using var duplicate = await Retry(); duplicate.EnsureSuccessStatusCode();
        var retained = (await f.Queue.ReadDetailAsync(job.Id))!; Assert.Equal(NotificationState.Pending, retained.Delivery.State);
        Assert.Equal("operator", Assert.Single(retained.Redrives).Actor); Assert.Single(retained.Attempts);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/dashboard/api/notifications?limit=101")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/dashboard/api/notifications?state=UnknownState")).StatusCode);
    }
    [Fact]
    public async Task InactiveRoutesCannotBeRetriedAndDeliveryDataContainsNoDestinationSecrets()
    {
        await using var f = await NotificationFixture.CreateAsync(); f.Clock.SetUtc(DateTimeOffset.UtcNow.AddMinutes(-1));
        f.Transport.OnSend = (_, _) => Task.FromResult(NotificationResult.Permanent("DestinationRejected")); await f.ObserveAsync("Offline"); await f.Dispatcher.RunOnceAsync();
        var job = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries);
        await using var host = await DashboardTestHost.StartAsync(f.Operations, configure: s => { Register(s, f); s.AddSingleton<INotificationMonitor>(new InactiveMonitor()); });
        using var client = host.Client(); await DashboardTestHost.LoginAsync(client);
        string detail = await client.GetStringAsync("/dashboard/api/notifications/" + job.Id);
        Assert.DoesNotContain("fingerprint", detail, StringComparison.OrdinalIgnoreCase); Assert.DoesNotContain("body", detail, StringComparison.OrdinalIgnoreCase);
        using var session = JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/session"));
        using var request = new HttpRequestMessage(HttpMethod.Post, "/dashboard/api/notifications/" + job.Id + "/retry"); request.Headers.Add("X-CSRF-TOKEN", session.RootElement.GetProperty("csrfToken").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await client.SendAsync(request)).StatusCode); Assert.Empty((await f.Queue.ReadDetailAsync(job.Id))!.Redrives);
    }
    [Fact]
    public async Task PausedDeliveryRetainsInspectableHistoryWithoutGrantingRetryAccess()
    {
        await using var f = await NotificationFixture.CreateAsync(); await f.ObserveAsync("Offline"); await f.CopyAsync();
        await using var host = await DashboardTestHost.StartAsync(f.Operations, configure: s => s.AddSingleton<INotificationReader>(f.Queue));
        using var client = host.Client(); await DashboardTestHost.LoginAsync(client);
        using var page = JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/notifications"));
        Assert.False(page.RootElement.GetProperty("worker").GetProperty("enabled").GetBoolean());
        Assert.Equal(1, page.RootElement.GetProperty("deliveries").GetArrayLength());
        Assert.Equal(1, page.RootElement.GetProperty("counts").GetProperty("pending").GetInt32());
    }
    private static void Register(IServiceCollection services, NotificationFixture f)
    {
        services.AddSingleton<INotificationQueue>(f.Queue); services.AddSingleton<INotificationReader>(f.Queue); services.AddSingleton<INotificationMonitor>(f.Dispatcher);
    }
    private sealed class InactiveMonitor : INotificationMonitor
    { public NotificationWorkerStatus Status => new(true, null, null, null, null, []); }
}
