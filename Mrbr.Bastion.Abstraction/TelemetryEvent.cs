using System.Text.Json.Serialization;

namespace Mrbr.Bastion.Abstraction;

/// <summary>The observation made by a telemetry source, without an inferred authorization decision.</summary>
public enum TelemetryEventKind
{
    /// <summary>A process was created.</summary>
    ProcessStarted,
    /// <summary>A process was already running when collection began.</summary>
    ProcessSnapshot,
    /// <summary>A process exited.</summary>
    ProcessStopped,
    /// <summary>A file create/open operation began; success is not implied.</summary>
    FileOpened,
    /// <summary>A file read operation began; success is not implied.</summary>
    FileRead,
    /// <summary>A file write operation began; success is not implied.</summary>
    FileWritten,
    /// <summary>A file object was closed.</summary>
    FileClosed,
    /// <summary>A file delete operation began; success is not implied.</summary>
    FileDeleted,
    /// <summary>A file rename operation began; the path is the source-reported path.</summary>
    FileRenamed,
    /// <summary>File metadata was queried.</summary>
    FileMetadataQueried
}

/// <summary>A copied, immutable observation. Unavailable identity and path information remains null.</summary>
public sealed record TelemetryEvent
{
    /// <summary>Creates a new observation with a fresh identity for callers outside the ETW callback.</summary>
    public TelemetryEvent() : this(Guid.NewGuid()) { }
    // Deserialization must use the retained identity without generating another OS-random GUID.
    /// <summary>Creates or restores an observation with an explicitly assigned identity.</summary>
    /// <param name="eventId">The identity to retain. Protocol validation rejects an empty identity.</param>
    [JsonConstructor]
    public TelemetryEvent(Guid eventId) => EventId = eventId;

    /// <summary>A unique event identifier, retained across delivery retries.</summary>
    public Guid EventId { get; init; }
    /// <summary>Source event time in UTC.</summary>
    public required DateTimeOffset TimestampUtc { get; init; }
    /// <summary>The kind of observation.</summary>
    public required TelemetryEventKind Kind { get; init; }
    /// <summary>The source-reported PID; this alone is not a durable process identity.</summary>
    public required int ProcessId { get; init; }
    /// <summary>A collector-local process lifetime identifier, when known.</summary>
    public Guid? ProcessInstanceId { get; init; }
    /// <summary>The parent PID, when reported.</summary>
    public int? ParentProcessId { get; init; }
    /// <summary>The parent's collector-local lifetime identifier, when known.</summary>
    public Guid? ParentProcessInstanceId { get; init; }
    /// <summary>The process name, when available.</summary>
    public string? ProcessName { get; init; }
    /// <summary>The executable path, which may be incomplete in source data.</summary>
    public string? ExecutablePath { get; init; }
    /// <summary>The command line, when reported by the source.</summary>
    public string? CommandLine { get; init; }
    /// <summary>The accessed path, possibly in Windows device-path form.</summary>
    public string? FilePath { get; init; }
    /// <summary>The file object address used for source correlation; it is not a stable file ID.</summary>
    public ulong? FileObject { get; init; }
    /// <summary>The requested I/O size, when reported.</summary>
    public long? SizeBytes { get; init; }
    /// <summary>The actual principal SID, if available. Never inferred from the collector's identity.</summary>
    public string? UserSid { get; init; }
    /// <summary>The source of this observation.</summary>
    public string Source { get; init; } = "Windows.Kernel.ETW";
    /// <summary>
    /// Historical parent context correlated at an observed creation event. Null for unknown or
    /// unverified startup relationships. Retained after the parent exits; never refreshed by PID.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ProcessParent? ParentProcess { get; init; }
}
