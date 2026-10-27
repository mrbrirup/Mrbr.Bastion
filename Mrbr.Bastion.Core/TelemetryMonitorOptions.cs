using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Core;

public sealed record TelemetryMonitorOptions
{
    public int QueueCapacity { get; init; } = 8192;
    public int BatchSize { get; init; } = 100;
    public TimeSpan FlushInterval { get; init; } = TimeSpan.FromSeconds(1);
    /// <summary>Return true to retain an event. Exceptions fault the run instead of silently losing evidence.</summary>
    public Func<TelemetryEvent, bool>? Filter { get; init; }

    public void Validate()
    {
        if (QueueCapacity is < 1 or > 1000000) throw new ArgumentOutOfRangeException(nameof(QueueCapacity));
        if (BatchSize is < 1 or > 10000) throw new ArgumentOutOfRangeException(nameof(BatchSize));
        if (FlushInterval <= TimeSpan.Zero || FlushInterval > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(FlushInterval));
    }
}
