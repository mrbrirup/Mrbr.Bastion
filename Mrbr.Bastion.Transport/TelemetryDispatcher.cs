using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Transport;

public sealed record TelemetryDispatcherOptions
{
    public int BatchSize { get; init; } = 16;
    public TimeSpan IdleInterval { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan InitialRetryDelay { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan MaximumRetryDelay { get; init; } = TimeSpan.FromSeconds(30);
}
public sealed record DeliveryHealth(long SettledBlocks, long TransientFailures, string? LastError);

/// <summary>Sequential at-least-once delivery. Only verified cache reconciliation settles evidence.</summary>
public sealed class TelemetryDispatcher
{
    private readonly ITelemetryCache _cache;
    private readonly ITelemetryTransport _transport;
    private readonly TelemetryDispatcherOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _started;
    private long _settled, _failures;
    private string? _lastError;
    public TelemetryDispatcher(ITelemetryCache cache, ITelemetryTransport transport, TelemetryDispatcherOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(transport);
        _cache = cache;
        _transport = transport;
        _options = options ?? new();
        if (_options.BatchSize is < 1 or > 1000 || _options.IdleInterval <= TimeSpan.Zero || _options.IdleInterval > TimeSpan.FromMinutes(1)
            || _options.InitialRetryDelay <= TimeSpan.Zero || _options.MaximumRetryDelay < _options.InitialRetryDelay
            || _options.MaximumRetryDelay > TimeSpan.FromMinutes(5)) throw new ArgumentOutOfRangeException(nameof(options));
    }
    public DeliveryHealth GetHealth() => new(Interlocked.Read(ref _settled), Interlocked.Read(ref _failures), Volatile.Read(ref _lastError));
    public async Task<int> DispatchPendingAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var pending = await _cache.ReadPendingAsync(_options.BatchSize, cancellationToken).ConfigureAwait(false);
            foreach (var block in pending)
            {
                var receipt = await _transport.SubmitAsync(block, cancellationToken).ConfigureAwait(false);
                await _cache.ReconcileAsync(receipt, cancellationToken).ConfigureAwait(false);
                Interlocked.Increment(ref _settled);
            }
            Volatile.Write(ref _lastError, null);
            return pending.Count;
        }
        catch (Exception error) { Volatile.Write(ref _lastError, error.Message); throw; }
        finally { _gate.Release(); }
    }
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _started, 1) != 0) throw new InvalidOperationException("A dispatcher can only run once.");
        double retry = _options.InitialRetryDelay.TotalMilliseconds;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    int count = await DispatchPendingAsync(cancellationToken).ConfigureAwait(false);
                    retry = _options.InitialRetryDelay.TotalMilliseconds;
                    if (count == 0) await Task.Delay(_options.IdleInterval, cancellationToken).ConfigureAwait(false);
                }
                catch (TelemetryTransportException error) when (error.IsTransient)
                {
                    Interlocked.Increment(ref _failures);
                    await Task.Delay(TimeSpan.FromMilliseconds(retry * (0.8 + Random.Shared.NextDouble() * 0.2)), cancellationToken).ConfigureAwait(false);
                    retry = Math.Min(retry * 2, _options.MaximumRetryDelay.TotalMilliseconds);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }
}
