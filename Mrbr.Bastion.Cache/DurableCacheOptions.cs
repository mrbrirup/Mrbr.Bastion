using Mrbr.Bastion.Abstraction;
namespace Mrbr.Bastion.Cache;

/// <summary>Capacity limits fail appends explicitly rather than deleting unsettled evidence.</summary>
public sealed record DurableCacheOptions
{
    public IBlockPayloadCodec[] AdditionalPayloadCodecs { get; init; } = [];
    public required string DatabasePath { get; init; }
    public required string NodeId { get; init; }
    public int MaximumEventsPerBlock { get; init; } = 1000;
    public int MaximumPayloadBytes { get; init; } = 4 * 1024 * 1024;
    /// <summary>Resident payload limit. Archived history is accounted separately; database overhead needs extra space.</summary>
    public long MaximumStoredPayloadBytes { get; init; } = 512L * 1024 * 1024;
    public CacheRetentionOptions Retention { get; init; } = new();
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
    internal Action<RetentionStage>? RetentionProbe { get; init; }

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(DatabasePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(NodeId);
        if (NodeId.Length > 256) throw new ArgumentOutOfRangeException(nameof(NodeId));
        if (MaximumEventsPerBlock is < 1 or > 10000) throw new ArgumentOutOfRangeException(nameof(MaximumEventsPerBlock));
        if (MaximumPayloadBytes is < 1 or > 64 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(MaximumPayloadBytes));
        if (MaximumStoredPayloadBytes < MaximumPayloadBytes) throw new ArgumentOutOfRangeException(nameof(MaximumStoredPayloadBytes));
        ArgumentNullException.ThrowIfNull(Retention); ArgumentNullException.ThrowIfNull(TimeProvider); Retention.Validate();
        if (Retention.Enabled && (Retention.MaximumSegmentPayloadBytes < MaximumPayloadBytes
            || Retention.MaximumSegmentFileBytes < MaximumPayloadBytes * 2L + 3L * 131072 + 32))
            throw new ArgumentException("Retention segment limits must accommodate a maximum-size block, receipt and manifest.");
        if (DatabasePath == ":memory:") throw new ArgumentException("A durable cache requires an on-disk database.", nameof(DatabasePath));
    }
}
