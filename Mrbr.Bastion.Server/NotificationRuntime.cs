using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Notifications;
using Mrbr.Bastion.Notifications.Sqlite;
using Mrbr.Bastion.Notifications.Smtp;
using Mrbr.Bastion.Notifications.Webhooks;

namespace Mrbr.Bastion.Server;

public sealed class NotificationSettings
{
    public bool Enabled { get; set; }
    public string? DatabasePath { get; set; }
    public int MaximumStoredDeliveries { get; set; } = 100000;
    public long MaximumReservedBytes { get; set; } = 1024L * 1024 * 1024;
    public int MaximumManualRedrives { get; set; } = 3;
    public int MaximumAttempts { get; set; } = 8;
    public int MaximumDeliveriesPerPass { get; set; } = 100;
    public int AttemptTimeoutSeconds { get; set; } = 30;
    public int LeaseDurationSeconds { get; set; } = 60;
    public int InitialRetryDelaySeconds { get; set; } = 5;
    public int MaximumRetryDelaySeconds { get; set; } = 900;
    public int PollIntervalSeconds { get; set; } = 5;
    public SmtpNotificationOptions[] Email { get; set; } = [];
    public WebhookNotificationOptions[] Webhooks { get; set; } = [];
}

internal sealed class NotificationRuntime : IAsyncDisposable
{
    public SqliteNotificationQueue Queue { get; private set; } = null!;
    public NotificationDispatcher Dispatcher { get; private set; } = null!;
    private readonly List<INotificationTransport> _transports = [];
    public static async Task<NotificationRuntime> OpenAsync(NotificationSettings settings, IAlertEventFeed feed, string root, string defaultDatabasePath)
    {
        var result = new NotificationRuntime();
        try
        {
            if (settings.PollIntervalSeconds is < 1 or > 300) throw new ArgumentOutOfRangeException(nameof(settings.PollIntervalSeconds));
            foreach (var smtp in settings.Email) result._transports.Add(new SmtpNotificationTransport(smtp));
            foreach (var webhook in settings.Webhooks) result._transports.Add(new WebhookNotificationTransport(webhook));
            result.Queue = await SqliteNotificationQueue.OpenAsync(new()
            {
                DatabasePath = Path.GetFullPath(settings.DatabasePath ?? defaultDatabasePath, root), MaximumStoredDeliveries = settings.MaximumStoredDeliveries,
                MaximumReservedBytes = settings.MaximumReservedBytes, MaximumManualRedrives = settings.MaximumManualRedrives
            });
            result.Dispatcher = new(feed, result.Queue, result._transports, new()
            {
                MaximumAttempts = settings.MaximumAttempts, MaximumDeliveriesPerPass = settings.MaximumDeliveriesPerPass,
                AttemptTimeout = TimeSpan.FromSeconds(settings.AttemptTimeoutSeconds), LeaseDuration = TimeSpan.FromSeconds(settings.LeaseDurationSeconds),
                InitialRetryDelay = TimeSpan.FromSeconds(settings.InitialRetryDelaySeconds), MaximumRetryDelay = TimeSpan.FromSeconds(settings.MaximumRetryDelaySeconds)
            });
            // Establish subscription cutoffs before the host starts evaluators or accepts acknowledgement requests.
            await result.Dispatcher.InitializeAsync(); return result;
        }
        catch { await result.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync()
    {
        foreach (var transport in _transports) transport.Dispose(); _transports.Clear();
        if (Queue is not null) await Queue.DisposeAsync();
    }
}
