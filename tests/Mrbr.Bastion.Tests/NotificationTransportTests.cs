using System.Text;
using Microsoft.AspNetCore.Http;
using MimeKit;
using Mrbr.Bastion.Notifications;
using Mrbr.Bastion.Notifications.Smtp;
using Mrbr.Bastion.Notifications.Webhooks;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class NotificationTransportTests
{
    private const string SigningKey = "test-only-webhook-signing-key-32-characters";
    [Fact]
    public async Task WebhookRetriesHonorRetryAfterAndKeepBodiesIdsAndValidSignaturesStable()
    {
        await using var f = await NotificationFixture.CreateAsync();
        await using var host = await NotificationWebhookHost.StartAsync((call, c) =>
        { if (call == 1) { c.Response.Headers.RetryAfter = "120"; return Task.FromResult<IResult>(Results.StatusCode(429)); } return Task.FromResult<IResult>(Results.Accepted()); });
        using var transport = new WebhookNotificationTransport(new() { RouteId = "webhook", Endpoint = host.Endpoint, AllowInsecureLoopback = true,
            SigningKey = SigningKey, SigningKeyId = "key-1", BearerToken = "test-only-bearer" }, f.Clock);
        var dispatcher = new NotificationDispatcher(f.Operations.Alerts, f.Queue, [transport], timeProvider: f.Clock, jitter: () => 0.5); await dispatcher.InitializeAsync();
        await f.ObserveAsync("Offline"); await dispatcher.RunOnceAsync();
        Assert.Equal(f.Clock.GetUtcNow().AddSeconds(120), Assert.Single((await f.Queue.ReadAsync(new())).Deliveries).NextAttemptUtc);
        f.Clock.Advance(TimeSpan.FromSeconds(119)); await dispatcher.RunOnceAsync(); Assert.Single(host.Requests);
        f.Clock.Advance(TimeSpan.FromSeconds(1)); await dispatcher.RunOnceAsync(); var requests = host.Requests.ToArray(); Assert.Equal(2, requests.Length);
        Assert.Equal(requests[0].Body, requests[1].Body); Assert.Equal(requests[0].Headers["Idempotency-Key"], requests[1].Headers["Idempotency-Key"]);
        Assert.NotEqual(requests[0].Headers["X-Bastion-Timestamp"], requests[1].Headers["X-Bastion-Timestamp"]);
        Assert.True(WebhookSignature.Verify(SigningKey, requests[1].Headers["X-Bastion-Timestamp"], requests[1].Body,
            requests[1].Headers["X-Bastion-Signature"], f.Clock.GetUtcNow(), TimeSpan.FromMinutes(5)));
        Assert.Equal("Bearer test-only-bearer", requests[1].Headers["Authorization"]); Assert.DoesNotContain("test-only-bearer", Encoding.UTF8.GetString(requests[1].Body));
        Assert.Equal(1, (await f.Queue.CountAsync()).Delivered);
    }
    [Theory]
    [InlineData(400, false)]
    [InlineData(401, false)]
    [InlineData(410, false)]
    [InlineData(408, true)]
    [InlineData(503, true)]
    public async Task WebhookClassifiesProviderFailuresWithoutRetainingResponseBodies(int status, bool retry)
    {
        await using var f = await NotificationFixture.CreateAsync(); await using var host = await NotificationWebhookHost.StartAsync((_, _) => Task.FromResult<IResult>(Results.Text("private-provider-response", statusCode: status)));
        using var transport = new WebhookNotificationTransport(new() { RouteId = "webhook", Endpoint = host.Endpoint, AllowInsecureLoopback = true });
        var dispatcher = new NotificationDispatcher(f.Operations.Alerts, f.Queue, [transport], timeProvider: f.Clock); await dispatcher.InitializeAsync();
        await f.ObserveAsync("Offline"); await dispatcher.RunOnceAsync(); var job = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries);
        Assert.Equal(retry ? NotificationState.Pending : NotificationState.DeadLetter, job.State);
        Assert.DoesNotContain("private-provider-response", job.LastCode!); Assert.Equal(status, Assert.Single((await f.Queue.ReadDetailAsync(job.Id))!.Attempts).RemoteStatus);
    }
    [Fact]
    public async Task WebhookNeverFollowsRedirectsAndCleartextRequiresNumericLoopbackOptIn()
    {
        await using var f = await NotificationFixture.CreateAsync(); await using var host = await NotificationWebhookHost.StartAsync((_, _) => Task.FromResult<IResult>(Results.Redirect("/moved", preserveMethod: true)));
        Assert.Throws<ArgumentException>(() => new WebhookNotificationTransport(new() { RouteId = "bad", Endpoint = host.Endpoint }));
        Assert.Throws<ArgumentException>(() => new WebhookNotificationTransport(new() { RouteId = "bad", Endpoint = new("http://localhost:5000/hook"), AllowInsecureLoopback = true }));
        Assert.Throws<ArgumentException>(() => new WebhookNotificationTransport(new() { RouteId = "bad", Endpoint = new("https://user:password@example.invalid/hook") }));
        using var transport = new WebhookNotificationTransport(new() { RouteId = "webhook", Endpoint = host.Endpoint, AllowInsecureLoopback = true });
        var dispatcher = new NotificationDispatcher(f.Operations.Alerts, f.Queue, [transport], timeProvider: f.Clock); await dispatcher.InitializeAsync();
        await f.ObserveAsync("Offline"); await dispatcher.RunOnceAsync(); Assert.Equal(0, host.RedirectTargetRequests);
        Assert.Equal("HttpRedirectRejected", Assert.Single((await f.Queue.ReadAsync(new())).Deliveries).LastCode);
    }
    [Fact]
    public void WebhookVerificationRejectsChangedPayloadsExpiredTimestampsAndUnknownSignatures()
    {
        byte[] body = Encoding.UTF8.GetBytes("test-body"); var now = DateTimeOffset.UtcNow; string timestamp = now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        string signature = WebhookSignature.Create(SigningKey, timestamp, body);
        Assert.True(WebhookSignature.Verify(SigningKey, timestamp, body, signature, now, TimeSpan.FromMinutes(5)));
        Assert.False(WebhookSignature.Verify(SigningKey, timestamp, Encoding.UTF8.GetBytes("changed"), signature, now, TimeSpan.FromMinutes(5)));
        Assert.False(WebhookSignature.Verify(SigningKey, timestamp, body, signature, now.AddMinutes(6), TimeSpan.FromMinutes(5)));
        Assert.False(WebhookSignature.Verify(SigningKey, timestamp, body, new string('x', 71), now, TimeSpan.FromMinutes(5)));
    }
    [Fact]
    public async Task SmtpLostAcknowledgementRetriesWithTheSameMessageIdAndOneRecipient()
    {
        await using var f = await NotificationFixture.CreateAsync(); await using var smtp = new NotificationSmtpHost(n => n == 1 ? 0 : 250);
        using var transport = new SmtpNotificationTransport(SmtpOptions(smtp)); var dispatcher = new NotificationDispatcher(f.Operations.Alerts, f.Queue, [transport], timeProvider: f.Clock, jitter: () => 0.5);
        await dispatcher.InitializeAsync(); await f.ObserveAsync("Offline"); await dispatcher.RunOnceAsync(); Assert.Equal(1, (await f.Queue.CountAsync()).Pending);
        f.Clock.Advance(TimeSpan.FromSeconds(5)); await dispatcher.RunOnceAsync(); var messages = smtp.Messages.ToArray(); Assert.Equal(2, messages.Length);
        using var first = MimeMessage.Load(new MemoryStream(messages[0])); using var second = MimeMessage.Load(new MemoryStream(messages[1]));
        Assert.Equal(first.MessageId, second.MessageId); Assert.Single(first.To.Mailboxes); Assert.Equal("operator@example.invalid", first.To.Mailboxes.Single().Address);
        Assert.Contains("Offline", first.TextBody); Assert.Equal(first.TextBody, second.TextBody); Assert.Equal(1, (await f.Queue.CountAsync()).Delivered);
    }
    [Theory]
    [InlineData(450, true)]
    [InlineData(550, false)]
    public async Task SmtpRecipientFailuresAreClassifiedIndependently(int status, bool retry)
    {
        await using var f = await NotificationFixture.CreateAsync(); await using var smtp = new NotificationSmtpHost(recipientStatus: status);
        using var transport = new SmtpNotificationTransport(SmtpOptions(smtp)); var dispatcher = new NotificationDispatcher(f.Operations.Alerts, f.Queue, [transport], timeProvider: f.Clock);
        await dispatcher.InitializeAsync(); await f.ObserveAsync("Offline"); await dispatcher.RunOnceAsync(); Assert.Empty(smtp.Messages);
        var job = Assert.Single((await f.Queue.ReadAsync(new())).Deliveries); Assert.Equal(retry ? NotificationState.Pending : NotificationState.DeadLetter, job.State);
        Assert.Equal(status, Assert.Single((await f.Queue.ReadDetailAsync(job.Id))!.Attempts).RemoteStatus);
    }
    [Fact]
    public async Task SmtpQuitFailureDoesNotRepeatAnAcceptedMessage()
    {
        await using var f = await NotificationFixture.CreateAsync(); await using var smtp = new NotificationSmtpHost(dropOnQuit: true);
        using var transport = new SmtpNotificationTransport(SmtpOptions(smtp)); var dispatcher = new NotificationDispatcher(f.Operations.Alerts, f.Queue, [transport], timeProvider: f.Clock);
        await dispatcher.InitializeAsync(); await f.ObserveAsync("Offline"); await dispatcher.RunOnceAsync(); f.Clock.Advance(TimeSpan.FromMinutes(1)); await dispatcher.RunOnceAsync();
        Assert.Single(smtp.Messages); Assert.Equal(1, (await f.Queue.CountAsync()).Delivered);
    }
    [Fact]
    public async Task RequiredStartTlsCannotFallBackToCleartextAndUnsafeMailboxesAreRejected()
    {
        await using var f = await NotificationFixture.CreateAsync(); await using var smtp = new NotificationSmtpHost();
        Assert.Throws<ArgumentException>(() => new SmtpNotificationTransport(SmtpOptions(smtp) with { Host = "example.invalid" }));
        Assert.Throws<ArgumentException>(() => new SmtpNotificationTransport(SmtpOptions(smtp) with { To = "operator@example.invalid\r\nBcc: hidden@example.invalid" }));
        using var transport = new SmtpNotificationTransport(SmtpOptions(smtp) with { Security = SmtpSecurity.StartTls, AllowInsecureLoopback = false });
        var dispatcher = new NotificationDispatcher(f.Operations.Alerts, f.Queue, [transport], timeProvider: f.Clock); await dispatcher.InitializeAsync();
        await f.ObserveAsync("Offline"); await dispatcher.RunOnceAsync(); Assert.Empty(smtp.Messages);
        Assert.Equal("SmtpRequiredTlsUnavailable", Assert.Single((await f.Queue.ReadAsync(new())).Deliveries).LastCode);
    }
    private static SmtpNotificationOptions SmtpOptions(NotificationSmtpHost host) => new()
    { RouteId = "email", Host = "127.0.0.1", Port = host.Port, Security = SmtpSecurity.InsecureLoopback, AllowInsecureLoopback = true, From = "bastion@example.invalid", To = "operator@example.invalid" };
}
