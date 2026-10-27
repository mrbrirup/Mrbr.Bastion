namespace Mrbr.Bastion.Abstraction;

/// <summary>A source which copies observations before invoking its callback.</summary>
public interface ITelemetrySource
{
    /// <summary>Cumulative source-reported loss. This does not include application queue overflow.</summary>
    long EventsLost { get; }
    /// <summary>Collects until cancellation or failure. No callbacks occur after this task completes.</summary>
    Task RunAsync(Action<TelemetryEvent> onEvent, CancellationToken cancellationToken = default);
}

/// <summary>A source that intentionally filters raw observations before materializing telemetry events.</summary>
public interface IFilteredTelemetrySource : ITelemetrySource
{
    /// <summary>Cumulative intentional exclusions. These are not queue drops or source losses.</summary>
    long FilteredEvents { get; }
}

/// <summary>The state of a single monitor run.</summary>
public enum MonitorState
{
    /// <summary>Collection has not started.</summary>
    Created,
    /// <summary>The source is starting or collecting.</summary>
    Running,
    /// <summary>The source has stopped and accepted events were drained.</summary>
    Stopped,
    /// <summary>Collection or persistence failed; inspect the error and unpersisted count.</summary>
    Faulted
}

/// <summary>Operational evidence, not a declaration that the host is uncompromised.</summary>
public sealed record MonitorHealth(
    MonitorState State,
    long ReceivedEvents,
    long FilteredEvents,
    long QueueDroppedEvents,
    long SourceLostEvents,
    long PersistedEvents,
    long PersistedBlocks,
    long UnpersistedEvents,
    string? LastError);

/// <summary>Connects a telemetry source to durable storage.</summary>
public interface ITelemetryMonitor
{
    /// <summary>Runs once. Cancellation stops the source, then drains accepted events to storage.</summary>
    Task RunAsync(CancellationToken cancellationToken = default);
    /// <summary>Returns cumulative counters for this run, including known loss.</summary>
    MonitorHealth GetHealth();
}
