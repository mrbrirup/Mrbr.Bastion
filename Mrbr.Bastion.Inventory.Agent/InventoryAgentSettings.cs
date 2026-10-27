using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Cache;

namespace Mrbr.Bastion.Inventory.Agent;

public sealed class InventoryAgentSettings
{
    public string NodeId{get;set;}="";
    public string CacheDatabasePath{get;set;}="";
    public string CrawlerDatabasePath{get;set;}="";
    public string NodePrivateKeyPath{get;set;}="";
    public string ReceiverPublicKeyPath{get;set;}="";
    public string? ServiceUri{get;set;}
    public string Transport{get;set;}="http";
    public bool AllowInsecureLoopback{get;set;}
    public bool Processes{get;set;}=true;
    public bool InstalledApplications{get;set;}=true;
    public bool IncludeCurrentUser{get;set;}
    public bool ProcessEvents{get;set;}
    public int EnrichmentQueueCapacity{get;set;}=1024;
    public int BaselineSeconds{get;set;}=60;
    public int MaximumConcurrentCrawlers{get;set;}=2;
    public int CrawlRepeatSeconds{get;set;}
    public long MaximumStoredPayloadBytes{get;set;}=512L*1024*1024;
    public CacheRetentionOptions Retention { get; set; } = new();
    public CrawlerTask[] Crawlers{get;set;}=[];
    public void Validate()
    {
        if(string.IsNullOrWhiteSpace(NodeId)||NodeId.Length>256||string.IsNullOrWhiteSpace(CacheDatabasePath)||string.IsNullOrWhiteSpace(CrawlerDatabasePath)
            ||string.IsNullOrWhiteSpace(NodePrivateKeyPath)||string.IsNullOrWhiteSpace(ReceiverPublicKeyPath)||Transport is not("http" or "grpc")
            ||BaselineSeconds is <10 or >86400||CrawlRepeatSeconds!=0&&CrawlRepeatSeconds is <60 or >2592000||EnrichmentQueueCapacity is <1 or >10000||MaximumConcurrentCrawlers is <1 or >8||Crawlers.Length>32
            ||Crawlers.Select(t=>t.Id).Distinct(StringComparer.Ordinal).Count()!=Crawlers.Length)throw new ArgumentException("Invalid inventory agent configuration.");
        foreach(var task in Crawlers)task.Validate();
        new DurableCacheOptions { NodeId=NodeId,DatabasePath=CacheDatabasePath,MaximumStoredPayloadBytes=MaximumStoredPayloadBytes,Retention=Retention }.Validate();
    }
}
