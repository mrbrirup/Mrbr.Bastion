using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Mrbr.Bastion.Notifications.Hosting;

public sealed record NotificationHostOptions
{ public int PollIntervalSeconds { get; init; } = 5; }
public static class NotificationHosting
{
    public static IServiceCollection AddBastionNotifications(this IServiceCollection services, NotificationDispatcher dispatcher,
        INotificationQueue queue, NotificationHostOptions? options = null)
    {
        options ??= new();
        if (options.PollIntervalSeconds is < 1 or > 300) throw new ArgumentOutOfRangeException(nameof(options));
        services.AddSingleton(options); services.AddSingleton(dispatcher); services.AddSingleton<INotificationMonitor>(dispatcher);
        services.AddSingleton(queue); services.AddSingleton<INotificationReader>(queue); services.AddHostedService<NotificationDeliveryWorker>(); return services;
    }
}
internal sealed class NotificationDeliveryWorker(NotificationDispatcher dispatcher, NotificationHostOptions options, ILogger<NotificationDeliveryWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(options.PollIntervalSeconds)); string? lastFailure = null;
        do
        {
            try
            {
                await dispatcher.RunOnceAsync(stoppingToken).ConfigureAwait(false);
                var status = dispatcher.Status; string? error = status.RoutingError ?? status.DeliveryError;
                if (error is not null && error != lastFailure) logger.LogWarning("Notification delivery needs operator attention: {Reason}", error);
                lastFailure = error;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception) { logger.LogError("Notification worker failed; durable leases and source events remain retained."); }
        } while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }
}
