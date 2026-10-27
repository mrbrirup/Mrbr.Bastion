namespace Mrbr.Bastion.Ingestion.Sqlite;

public sealed record SqliteIngestionOptions
{
    public required string DatabasePath { get; init; }
    /// <summary>Retained payload limit; database pages, indexes, receipts and WAL require additional space.</summary>
    public long MaximumStoredPayloadBytes { get; init; } = 4L * 1024 * 1024 * 1024;
    public IngestionOptions BlockLimits { get; init; } = new();
    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(DatabasePath);
        if (DatabasePath == ":memory:") throw new ArgumentException("Central ingestion requires an on-disk database.");
        BlockLimits.Validate();
        if (MaximumStoredPayloadBytes < BlockLimits.MaximumPayloadBytes) throw new ArgumentOutOfRangeException(nameof(MaximumStoredPayloadBytes));
    }
}
