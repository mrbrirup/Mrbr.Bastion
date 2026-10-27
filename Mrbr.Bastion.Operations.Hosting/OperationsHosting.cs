using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Mrbr.Bastion.Operations.Hosting;

public sealed record OperationsHostOptions
{ public int AlertEvaluationIntervalSeconds { get; init; } = 15; }
public static class OperationsHosting
{
    public static IServiceCollection AddBastionOperations(this IServiceCollection services, OperationsHostOptions? options = null)
    {
        options ??= new();
        if (options.AlertEvaluationIntervalSeconds is < 1 or > 300) throw new ArgumentOutOfRangeException(nameof(options));
        services.TryAddSingleton(options); services.TryAddSingleton<OperationsService>(); services.TryAddSingleton<AlertEvaluator>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, AlertEvaluationWorker>()); return services;
    }
}
internal sealed class AlertEvaluationWorker(AlertEvaluator evaluator, OperationsHostOptions options, ILogger<AlertEvaluationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(options.AlertEvaluationIntervalSeconds));
        do
        {
            try { await evaluator.EvaluateAsync(stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception error) { logger.LogError(error, "Central alert evaluation failed; retained conditions remain available."); }
        } while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }
}
