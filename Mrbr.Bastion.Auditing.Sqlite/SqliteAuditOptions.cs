namespace Mrbr.Bastion.Auditing.Sqlite;

public sealed record SqliteAuditOptions
{
    public required string DatabasePath { get; init; }
    public int MaximumStoredAudits { get; init; } = 100000;
    /// <summary>Logical envelope bytes; SQLite pages, indexes, and WAL need additional space.</summary>
    public long MaximumStoredBytes { get; init; } = 1024L * 1024 * 1024;
    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(DatabasePath);
        if (DatabasePath == ":memory:" || MaximumStoredAudits < 1 || MaximumStoredBytes < 4L * Contracts.AuditProtocol.MaximumEnvelopeBytes)
            throw new ArgumentOutOfRangeException(nameof(SqliteAuditOptions));
    }
}
