using System.ComponentModel;

namespace Mrbr.Bastion.Cache;

public sealed record CacheRetentionOptions
{
    [Description("Opt in to archiving a verified contiguous settled prefix. Unsettled blocks and archive evidence are never automatically deleted.")]
    public bool Enabled { get; set; }
    [Description("Archive root, relative to the cache database folder or absolute. Empty reuses the recorded location, or <database>.archives for new archives. Each ledger gets its own subfolder. Configure a new location explicitly when relocating a backup.")]
    public string ArchiveDirectory { get; set; } = "";
    [Description("Keep at least this many newest blocks resident, including unsettled blocks. Older blocks still require verified receipts and the minimum age.")]
    public int KeepRecentBlocks { get; set; } = 128;
    [Description("Minimum age of both a block and its signed settlement receipt before archiving. Zero allows immediate settled-prefix archiving.")]
    public int MinimumAgeSeconds { get; set; } = 60;
    [Description("Automatic maintenance interval. Capacity pressure also attempts eligible retention before rejecting an append.")]
    public int IntervalSeconds { get; set; } = 30;
    [Description("Maximum blocks copied into one signed archive segment, from 1 to 10,000. Payload and file byte limits can close a segment sooner.")]
    public int MaximumBlocksPerSegment { get; set; } = 1024;
    [Description("Maximum combined original payload bytes in one segment. Must accommodate a maximum-size block; JSON, signatures and receipts consume additional file space.")]
    public long MaximumSegmentPayloadBytes { get; set; } = 16L * 1024 * 1024;
    [Description("Maximum complete archive file size, including framing, original JSON, receipts and signed manifest. Must allow overhead beyond the maximum block payload.")]
    public long MaximumSegmentFileBytes { get; set; } = 64L * 1024 * 1024;
    [Description("Maximum segments published in one maintenance pass. Later automatic or manual passes continue from the committed archive head.")]
    public int MaximumSegmentsPerRun { get; set; } = 8;
    [Description("Archive file quota, including all published segments. Zero means no configured quota. Reaching it preserves resident evidence and reports failure; archives are never expired automatically.")]
    public long MaximumArchiveBytes { get; set; } = 10L * 1024 * 1024 * 1024;

    public void Validate()
    {
        if (ArchiveDirectory is null || KeepRecentBlocks is < 0 or > 1000000 || MinimumAgeSeconds is < 0 or > 31536000
            || IntervalSeconds is < 1 or > 86400 || MaximumBlocksPerSegment is < 1 or > 10000
            || MaximumSegmentsPerRun is < 1 or > 1024 || MaximumSegmentPayloadBytes is < 1 or > 1024L * 1024 * 1024
            || MaximumSegmentFileBytes is < 262144 or > 2L * 1024 * 1024 * 1024 || MaximumArchiveBytes < 0)
            throw new ArgumentException("Invalid cache retention configuration.");
    }
}

public sealed record CacheStorageStatus(long ResidentBlocks, long ResidentPayloadBytes, long ArchivedBlocks,
    long ArchivedPayloadBytes, long ArchiveFileBytes, long ArchiveSegments, string ArchiveDirectory, string? LastRetentionError);
public sealed record CacheRetentionResult(long ArchivedBlocks, long ArchivedPayloadBytes, long NewSegments, CacheStorageStatus Storage);
internal enum RetentionStage { ArchiveFlushed, BeforePruneCommit, AfterPruneCommit }
