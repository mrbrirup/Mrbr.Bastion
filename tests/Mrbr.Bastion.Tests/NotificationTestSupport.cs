using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Notifications;
using Mrbr.Bastion.Notifications.Sqlite;

namespace Mrbr.Bastion.Tests;

internal sealed class DelegateNotificationTransport : INotificationTransport
{
    public NotificationRoute Route { get; }
    public List<(AlertNotification Message, byte[] Body)> Sent { get; } = [];
    public Func<AlertNotification, CancellationToken, Task<NotificationResult>> OnSend { get; set; } = (_, _) => Task.FromResult(NotificationResult.Accepted());
    public DelegateNotificationTransport(string id = "test-route", bool replay = false, bool includeAck = false, AlertSeverity minimum = AlertSeverity.Warning, string? fingerprint = null)
    { Route = new(id, fingerprint ?? NotificationRoute.HashDestination("test", id), replay, minimum, includeAck); }
    public Task<NotificationResult> SendAsync(AlertNotification notification, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default)
    { Sent.Add((notification, body.ToArray())); return OnSend(notification, cancellationToken); }
    public void Dispose() { }
}
internal sealed class NotificationFixture : IAsyncDisposable
{
    public OperationsFixture Operations { get; private set; } = null!;
    public SqliteNotificationQueue Queue { get; private set; } = null!;
    public DelegateNotificationTransport Transport { get; private set; } = null!;
    public NotificationDispatcher Dispatcher { get; private set; } = null!;
    public AuditClock Clock => Operations.Audits.Clock;
    public string DatabasePath => Path.Combine(Operations.Audits.Ledger.Local.DirectoryPath, "notifications.db");
    public static async Task<NotificationFixture> CreateAsync(NotificationDispatcherOptions? policy = null, bool includeAcknowledgements = false, SqliteNotificationOptions? options = null)
    {
        var f = new NotificationFixture();
        try
        {
            f.Operations = await OperationsFixture.CreateAsync(); f.Transport = new(includeAck: includeAcknowledgements);
            f.Queue = await SqliteNotificationQueue.OpenAsync(options ?? new() { DatabasePath = f.DatabasePath });
            f.Dispatcher = new(f.Operations.Alerts, f.Queue, [f.Transport], policy, f.Clock, () => 0.5);
            await f.Dispatcher.InitializeAsync(); return f;
        }
        catch { await f.DisposeAsync(); throw; }
    }
    public Task ObserveAsync(params string[] conditions) => Operations.Alerts.ApplyAsync(new(Operations.NodeId, Operations.LedgerId, Clock.GetUtcNow(),
        conditions.Select(c => new AlertCondition(c, c is "Offline" or "CollectorFaulted" ? AlertSeverity.Critical : AlertSeverity.Warning)).ToArray(), true));
    public async Task CopyAsync(NotificationRoute? route = null, int maximumAttempts = 8)
    {
        route ??= Transport.Route;
        var subscription = await Queue.ReadSubscriptionAsync(route.Id);
        await Queue.AppendAsync(route, subscription.Cursor, await Operations.Alerts.ReadChangesAsync(subscription.Cursor), Clock.GetUtcNow(), maximumAttempts);
    }
    public async Task ReopenAsync(SqliteNotificationOptions? options = null)
    { await Queue.DisposeAsync(); Queue = await SqliteNotificationQueue.OpenAsync(options ?? new() { DatabasePath = DatabasePath }); }
    public async ValueTask DisposeAsync()
    { if (Queue is not null) await Queue.DisposeAsync(); if (Operations is not null) await Operations.DisposeAsync(); }
}
