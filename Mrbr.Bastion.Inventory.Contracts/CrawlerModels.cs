namespace Mrbr.Bastion.Inventory.Contracts;

public sealed record CrawlerTask
{
    public required string Id { get; init; }
    public required string Root { get; init; }
    public bool Enabled{get;init;}=true;
    public int Priority { get; init; } = 0;
    public int WorkPerRound { get; init; } = 20;
    public int DelayMilliseconds { get; init; } = 50;
    public int MaximumWorkItems { get; init; } = 100000;
    public int MaximumArchiveDepth { get; init; } = 3;
    public int MaximumArchiveEntries { get; init; } = 10000;
    public int MaximumEntryBytes { get; init; } = 16*1024*1024;
    public long MaximumExpandedBytes { get; init; } = 128*1024*1024;
    public int MaximumCompressionRatio { get; init; } = 100;
    public int MaximumArchiveSeconds { get; init; } = 30;
    public string[] ExcludedDirectories { get; init; } = [];
    public string[] Extensions { get; init; } = [".exe",".dll",".jar",".zip",".tar",".gz"];
    public void Validate()
    {
        if(string.IsNullOrWhiteSpace(Id)||Id.Length>64||Id.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c is not('-' or '_'))
            ||Root.Length>4096||!Path.IsPathFullyQualified(Root)||WorkPerRound is <1 or >1000||DelayMilliseconds is <0 or >60000
            ||MaximumWorkItems is <1 or >1000000||MaximumArchiveDepth is <0 or >5||MaximumArchiveEntries is <1 or >100000
            ||MaximumEntryBytes is <1024 or >64*1024*1024||MaximumExpandedBytes<MaximumEntryBytes||MaximumExpandedBytes>1024L*1024*1024
            ||MaximumCompressionRatio is <1 or >10000||MaximumArchiveSeconds is <1 or >300||Extensions.Length is <1 or >32
            ||Extensions.Any(e=>e.Length>16||!e.StartsWith('.')||e.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c!='.'))
            ||ExcludedDirectories.Length>100)throw new ArgumentException("Invalid crawler configuration.");
        foreach(var exclusion in ExcludedDirectories)if(!Path.IsPathFullyQualified(exclusion)||exclusion.Length>4096)throw new ArgumentException("Exclusions require absolute paths.");
    }
    [System.Text.Json.Serialization.JsonIgnore]
    public string Fingerprint=>InventoryJson.Hash(System.Text.Json.JsonSerializer.Serialize(this));
}
public sealed record CrawlerState(string TaskId,string Fingerprint,Guid ScanId,bool Started,bool Finished,bool Partial,long Pending,long Completed);
public sealed record CrawlerWork(long Id,string Path);
public interface ICrawlerJournal
{
    Task<CrawlerState> InitializeAsync(CrawlerTask task,CancellationToken cancellationToken=default);
    Task<CrawlerState> StateAsync(string taskId,CancellationToken cancellationToken=default);
    Task MarkStartedAsync(string taskId,CancellationToken cancellationToken=default);
    Task<CrawlerWork?> NextAsync(string taskId,CancellationToken cancellationToken=default);
    Task EnqueueAsync(string taskId,string path,int maximum,CancellationToken cancellationToken=default);
    Task FinishWorkAsync(string taskId,long id,bool partial,CancellationToken cancellationToken=default);
    Task FinishAsync(string taskId,CancellationToken cancellationToken=default);
    Task RestartCompletedAsync(CrawlerTask task,CancellationToken cancellationToken=default);
}
