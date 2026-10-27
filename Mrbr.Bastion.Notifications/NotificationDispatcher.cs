using Mrbr.Bastion.Alerting;

namespace Mrbr.Bastion.Notifications;

public sealed record NotificationDispatcherOptions
{
    public int MaximumAttempts { get; init; } = 8;
    public int MaximumDeliveriesPerPass { get; init; } = 100;
    public TimeSpan AttemptTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan LeaseDuration { get; init; } = TimeSpan.FromSeconds(60);
    public TimeSpan InitialRetryDelay { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan MaximumRetryDelay { get; init; } = TimeSpan.FromMinutes(15);
    public void Validate()
    {
        if (MaximumAttempts is < 1 or > 25 || MaximumDeliveriesPerPass is < 1 or > 1000
            || AttemptTimeout < TimeSpan.FromMilliseconds(100) || AttemptTimeout > TimeSpan.FromMinutes(5)
            || LeaseDuration < AttemptTimeout + TimeSpan.FromSeconds(5) || LeaseDuration > TimeSpan.FromMinutes(10)
            || InitialRetryDelay <= TimeSpan.Zero || MaximumRetryDelay < InitialRetryDelay || MaximumRetryDelay > TimeSpan.FromHours(24))
            throw new ArgumentOutOfRangeException(nameof(NotificationDispatcherOptions));
    }
}

/// <summary>Copies immutable events before advancing a durable cursor, then independently delivers due outbox entries.</summary>
public sealed class NotificationDispatcher : INotificationMonitor
{
    private readonly IAlertEventFeed _feed;
    private readonly INotificationQueue _queue;
    private readonly Dictionary<string, INotificationTransport> _transports;
    private readonly NotificationDispatcherOptions _options;
    private readonly TimeProvider _time;
    private readonly Func<double> _jitter;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private NotificationWorkerStatus _status;
    private bool _initialized;
    public NotificationWorkerStatus Status => Volatile.Read(ref _status);
    public NotificationDispatcher(IAlertEventFeed feed, INotificationQueue queue, IEnumerable<INotificationTransport> transports,
        NotificationDispatcherOptions? options = null, TimeProvider? timeProvider = null, Func<double>? jitter = null)
    {
        _feed = feed; _queue = queue; _options = options ?? new(); _options.Validate(); _time = timeProvider ?? TimeProvider.System;
        _jitter = jitter ?? Random.Shared.NextDouble;
        _transports = transports.ToDictionary(t => t.Route.Id, StringComparer.Ordinal);
        if (_transports.Count is < 1 or > 1000) throw new ArgumentException("Configure 1 to 1000 unique notification destinations.", nameof(transports));
        foreach (var transport in _transports.Values) transport.Route.Validate();
        _status = new(true, null, null, null, null, _transports.Keys.ToArray());
    }
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_initialized) return;
            var position = await _feed.ReadPositionAsync(cancellationToken).ConfigureAwait(false);
            foreach (var transport in _transports.Values) await _queue.RegisterAsync(transport.Route, position, cancellationToken).ConfigureAwait(false);
            _initialized = true;
        }
        finally { _gate.Release(); }
    }
    public async Task RunOnceAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_initialized) throw new InvalidOperationException("Initialize notification subscriptions before starting alert evaluation or accepting operator actions.");
            var started = _time.GetUtcNow(); _status = _status with { LastStartedUtc = started };
            string? routingError = null, deliveryError = null;
            foreach (var transport in _transports.Values)
            {
                try
                {
                    var subscription = await _queue.ReadSubscriptionAsync(transport.Route.Id, cancellationToken).ConfigureAwait(false);
                    var page = await _feed.ReadChangesAsync(subscription.Cursor, 100, cancellationToken).ConfigureAwait(false);
                    await _queue.AppendAsync(transport.Route, subscription.Cursor, page, _time.GetUtcNow(), _options.MaximumAttempts, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception) { routingError = "AlertEventRoutingOrCapacityUnavailable"; }
            }
            // A routing/capacity problem must not prevent already admitted deliveries from draining.
            for (int i = 0; i < _options.MaximumDeliveriesPerPass; i++)
            {
                try
                {
                    var lease = await _queue.LeaseAsync(_transports.Keys.ToArray(), _time.GetUtcNow(), _options.LeaseDuration, cancellationToken).ConfigureAwait(false);
                    if (lease is null) break;
                    NotificationResult result;
                    using (var deadline = new CancellationTokenSource(_options.AttemptTimeout, _time))
                    using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token))
                    {
                        try { result = await _transports[lease.Delivery.RouteId].SendAsync(NotificationJson.Decode(lease.Body), lease.Body, linked.Token).ConfigureAwait(false); }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                        catch (OperationCanceledException) { result = NotificationResult.Retry("AttemptTimedOut"); }
                        catch (Exception) { result = NotificationResult.Retry("TransportFailure"); }
                    }
                    if (result is null || string.IsNullOrEmpty(result.Code) || result.Code.Length > 64 || result.Code.Any(c => !char.IsAsciiLetterOrDigit(c))
                        || !Enum.IsDefined(result.Disposition) || result.RemoteStatus is < 100 or > 599) result = NotificationResult.Retry("InvalidTransportOutcome");
                    var now = _time.GetUtcNow(); var delay = result.Disposition == NotificationDisposition.Retry ? RetryDelay(lease.Delivery.CycleAttempts, result.RetryAfter) : TimeSpan.Zero;
                    // Preserve a provider acknowledgement even if host shutdown begins after SendAsync returns.
                    await _queue.CompleteAsync(lease, result, now, now + delay, CancellationToken.None).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception) { deliveryError = "NotificationLeaseOrPersistenceUnavailable"; break; }
            }
            _status = new(true, started, _time.GetUtcNow(), routingError, deliveryError, _transports.Keys.ToArray());
        }
        finally { _gate.Release(); }
    }
    private TimeSpan RetryDelay(int cycleAttempts, TimeSpan? requested)
    {
        double jitter = Math.Clamp(_jitter(), 0, 1);
        double milliseconds = Math.Min(_options.MaximumRetryDelay.TotalMilliseconds,
            _options.InitialRetryDelay.TotalMilliseconds * Math.Pow(2, Math.Clamp(cycleAttempts - 1, 0, 24)) * (0.8 + jitter * 0.4));
        milliseconds = Math.Max(milliseconds, requested?.TotalMilliseconds ?? 0);
        return TimeSpan.FromMilliseconds(Math.Clamp(milliseconds, 0, TimeSpan.FromDays(1).TotalMilliseconds));
    }
}
