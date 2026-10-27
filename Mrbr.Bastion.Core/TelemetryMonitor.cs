using System.Runtime.ExceptionServices;
using System.Threading.Channels;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Core;

/// <summary>
/// A single-run bounded collection pipeline. Source callbacks never wait for disk I/O.
/// Overflow is counted, persistence errors fault the run, and normal cancellation drains accepted events.
/// The caller owns the source and cache lifetimes.
/// </summary>
public sealed class TelemetryMonitor : ITelemetryMonitor
{
    private readonly ITelemetrySource _source;
    private readonly ITelemetryCache _cache;
    private readonly TelemetryMonitorOptions _options;
    private readonly Channel<TelemetryEvent> _queue;
    private int _state;
    private long _received, _filtered, _dropped, _persisted, _blocks;
    private string? _lastError;

    public TelemetryMonitor(ITelemetrySource source, ITelemetryCache cache, TelemetryMonitorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(cache);
        _source = source;
        _cache = cache;
        _options = options ?? new TelemetryMonitorOptions();
        _options.Validate();
        _queue = Channel.CreateBounded<TelemetryEvent>(new BoundedChannelOptions(_options.QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false
        });
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _state, (int)MonitorState.Running, (int)MonitorState.Created) != (int)MonitorState.Created)
            throw new InvalidOperationException("A monitor instance can only run once.");
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task consumer = DrainAsync();
        Task producer;
        try { producer = _source.RunAsync(OnEvent, stop.Token); }
        catch (Exception error) { producer = Task.FromException(error); }
        Exception? failure = null;
        try
        {
            var first = await Task.WhenAny(producer, consumer).ConfigureAwait(false);
            if (first == consumer)
            {
                try { await stop.CancelAsync().ConfigureAwait(false); }
                catch (Exception error) { failure = error; }
            }
            try { await producer.ConfigureAwait(false); }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (Exception error) { failure = failure is null ? error : new AggregateException(failure, error); }
            finally { _queue.Writer.TryComplete(); }
            try { await consumer.ConfigureAwait(false); }
            catch (Exception error) { failure = failure is null ? error : new AggregateException(failure, error); }
            if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
            Volatile.Write(ref _state, (int)MonitorState.Stopped);
        }
        catch (Exception error)
        {
            Volatile.Write(ref _lastError, error.ToString());
            Volatile.Write(ref _state, (int)MonitorState.Faulted);
            throw;
        }
    }

    public MonitorHealth GetHealth()
    {
        long sourceFiltered = (_source as IFilteredTelemetrySource)?.FilteredEvents ?? 0;
        long received = Interlocked.Read(ref _received) + sourceFiltered;
        long filtered = Interlocked.Read(ref _filtered) + sourceFiltered;
        long dropped = Interlocked.Read(ref _dropped);
        long persisted = Interlocked.Read(ref _persisted);
        return new MonitorHealth((MonitorState)Volatile.Read(ref _state), received, filtered, dropped,
            _source.EventsLost, persisted, Interlocked.Read(ref _blocks),
            Math.Max(0, received - filtered - dropped - persisted), Volatile.Read(ref _lastError));
    }

    private void OnEvent(TelemetryEvent item)
    {
        Interlocked.Increment(ref _received);
        if (_options.Filter is not null && !_options.Filter(item))
        {
            Interlocked.Increment(ref _filtered);
            return;
        }
        // Wait-mode + TryWrite makes rejection observable. DropWrite-mode would report success even when dropping.
        if (!_queue.Writer.TryWrite(item)) Interlocked.Increment(ref _dropped);
    }

    private async Task DrainAsync()
    {
        var batch = new List<TelemetryEvent>(_options.BatchSize);
        while (await _queue.Reader.WaitToReadAsync().ConfigureAwait(false))
        {
            using var deadline = new CancellationTokenSource(_options.FlushInterval);
            while (batch.Count < _options.BatchSize)
            {
                while (batch.Count < _options.BatchSize && _queue.Reader.TryRead(out var item)) batch.Add(item);
                if (batch.Count == _options.BatchSize) break;
                try
                {
                    if (!await _queue.Reader.WaitToReadAsync(deadline.Token).ConfigureAwait(false)) break;
                }
                catch (OperationCanceledException) when (deadline.IsCancellationRequested) { break; }
            }
            if (batch.Count == 0) continue;
            // Shutdown cancellation does not abort the final commit. A storage failure remains an observable fault.
            await _cache.AppendAsync(batch, CancellationToken.None).ConfigureAwait(false);
            Interlocked.Add(ref _persisted, batch.Count);
            Interlocked.Increment(ref _blocks);
            batch.Clear();
        }
    }
}
