using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Ingestion;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Vulnerabilities;
using Mrbr.Bastion.Vulnerabilities.Sqlite;

namespace Mrbr.Bastion.Software.Hosting;

public sealed class SoftwareSettings
{
    public bool Enabled{get;set;}
    public string? InventoryDatabasePath{get;set;}
    public string? ExposureDatabasePath{get;set;}
    public int MaximumItems{get;set;}=100000;
    public int MaximumFindings{get;set;}=100000;
    public bool IntelligenceEnabled{get;set;}
    public string? NvdApiKey{get;set;}
    public int PollSeconds{get;set;}=5;
    public int ObservationLifetimeSeconds{get;set;}=86400;
    public int IntelligenceLifetimeSeconds{get;set;}=86400;
    public int RefreshSeconds{get;set;}=21600;
    public ProductMapping[] Mappings{get;set;}=[];
    public void Validate(){if(PollSeconds is <1 or >3600||ObservationLifetimeSeconds is <60 or >2592000||IntelligenceLifetimeSeconds is <60 or >2592000||RefreshSeconds is <60 or >604800)throw new ArgumentException("Invalid software evaluation intervals.");foreach(var m in Mappings)MappingValidation.Validate(m);}
}
public sealed record SoftwareEnrollment(string NodeId,Guid LedgerId);
/// <summary>Rebuildable projection of verified ledger evidence and independent exposure alert evaluation.</summary>
public sealed class SoftwareRuntime : BackgroundService,ISoftwareMonitor
{
    private readonly IIngestionStore _ledger;private readonly SqliteInventoryStore _inventory;private readonly SqliteExposureStore _exposures;
    private readonly IAlertStore _alerts;private readonly SoftwareEnrollment[] _nodes;private readonly SoftwareSettings _options;private readonly IVulnerabilityProvider? _provider;
    private readonly ExposureCorrelator _correlator;private readonly ILogger<SoftwareRuntime> _logger;private readonly SemaphoreSlim _gate=new(1,1);
    private readonly Dictionary<SoftwareEnrollment,long> _cursors=[];private int _mappingCursor;
    public SoftwareStatus Status{get;private set;}
    public SoftwareRuntime(IIngestionStore ledger,SqliteInventoryStore inventory,SqliteExposureStore exposures,IAlertStore alerts,
        SoftwareEnrollment[] nodes,SoftwareSettings options,IVulnerabilityProvider? provider,ILogger<SoftwareRuntime> logger)
    {
        options.Validate();_ledger=ledger;_inventory=inventory;_exposures=exposures;_alerts=alerts;_nodes=nodes;_options=options;_provider=provider;_logger=logger;
        _correlator=new(TimeSpan.FromSeconds(options.ObservationLifetimeSeconds),TimeSpan.FromSeconds(options.IntelligenceLifetimeSeconds));Status=new(true,null,null,null,provider is not null,ExposureAlertPolicy.Version);
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while(!stoppingToken.IsCancellationRequested)
        {
            try{await RunOnceAsync(stoppingToken);}
            catch(OperationCanceledException)when(stoppingToken.IsCancellationRequested){break;}
            catch(Exception e){Status=Status with{Error="SoftwareEvidenceOrStorageUnavailable"};_logger.LogError(e,"Software inventory or exposure evaluation failed.");}
            try{await Task.Delay(TimeSpan.FromSeconds(_options.PollSeconds),stoppingToken);}catch(OperationCanceledException)when(stoppingToken.IsCancellationRequested){break;}
        }
    }
    public async Task RunOnceAsync(CancellationToken ct=default)
    {
        await _gate.WaitAsync(ct);try
        {
            foreach(var node in _nodes)
            {
                try
                {
                    var cursor=await _inventory.CheckpointAsync(node.NodeId,node.LedgerId,ct);
                    if(cursor.SequenceNumber>0)
                    {var anchor=await _ledger.ReadAsync(node.NodeId,node.LedgerId,cursor.SequenceNumber,ct);if(anchor?.Block.BlockHash!=cursor.BlockHash)throw new InvalidDataException("Inventory projection anchor no longer matches retained signed evidence.");}
                    for(int n=0;n<100;n++)
                    {var next=await _ledger.ReadAsync(node.NodeId,node.LedgerId,cursor.SequenceNumber+1,ct);if(next is null)break;await _inventory.ApplyAsync(next.Block,next.Receipt.Content.AcceptedUtc,ct);cursor=new(node.NodeId,node.LedgerId,next.Block.Content.SequenceNumber,next.Block.BlockHash);}
                }
                catch(OperationCanceledException){throw;}
                catch
                {await _alerts.ApplyAsync(new(node.NodeId,node.LedgerId,DateTimeOffset.UtcNow,[],false,AlertCategory.Exposure,"runtime:"),ct);throw;}
            }
            Status=Status with{LastProjectionUtc=DateTimeOffset.UtcNow,Error=null};
            var mappings=await _exposures.ReadMappingsAsync(ct);
            if(_provider is not null&&mappings.Length>0)
            {
                var mapping=mappings[_mappingCursor%mappings.Length];_mappingCursor=(_mappingCursor+1)%mappings.Length;var progress=await _exposures.ReadProgressAsync(mapping.Id,ct);var now=DateTimeOffset.UtcNow;
                if(progress is null||progress.NextAttemptUtc<=now)
                {
                    try{var page=await _provider.FetchPageAsync(mapping,progress?.NextIndex??0,200,ct);await _exposures.StorePageAsync(mapping,progress?.NextIndex??0,page.Records,page.Total,DateTimeOffset.UtcNow,TimeSpan.FromSeconds(_options.RefreshSeconds),ct);}
                    catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
                    catch(Exception e){await _exposures.FailRefreshAsync(mapping,DateTimeOffset.UtcNow,ct);Status=Status with{Error="IntelligenceRefreshFailed"};_logger.LogWarning(e,"NVD refresh failed for reviewed mapping {MappingId}.",mapping.Id);}
                }
            }
            var snapshots=new List<IntelligenceSnapshot>();foreach(var mapping in mappings)snapshots.Add(await _exposures.ReadSnapshotAsync(mapping,ct));
            foreach(var node in _nodes)
            {
                var page=await _inventory.ReadAsync(node.NodeId,node.LedgerId,_cursors.GetValueOrDefault(node),10,cancellationToken:ct);
                foreach(var item in page.Items)
                {
                    var now=DateTimeOffset.UtcNow;var current=_correlator.Evaluate(item,mappings,snapshots.ToArray(),now).ToList();
                    foreach(var previous in await _exposures.ReadItemAsync(node.NodeId,node.LedgerId,item.Key,ct))
                        if(!current.Any(f=>f.Id==previous.Id))current.Add(previous with{Applicability=_correlator.IsConfirmedAbsent(item,now)?Applicability.NotAffected:Applicability.Unknown,Reason=_correlator.IsConfirmedAbsent(item,now)?"AbsentFromCompleteScope":"PublishedMatchNoLongerAvailable",EvaluatedUtc=now,RecentlyRunning=false});
                    foreach(var finding in current)await _exposures.SaveAsync(finding,ct);
                    string prefix=item.Key+":";var conditions=new List<AlertCondition>();
                    foreach(var finding in current.Where(f=>f.CveId is not null&&f.Applicability!=Applicability.NotAffected))
                        conditions.Add(new("SoftwareExposure",finding.Cvss>=9?AlertSeverity.Critical:AlertSeverity.Warning,prefix+finding.CveId,finding.Applicability==Applicability.Unknown));
                    if(current.Any(f=>f.Applicability==Applicability.Unknown&&(f.CveId is not null||f.MappingId is not null&&_provider is not null)))conditions.Add(new("ExposureDataUnavailable",AlertSeverity.Warning,prefix+"data"));
                    await _alerts.ApplyAsync(new(node.NodeId,node.LedgerId,now,conditions.ToArray(),true,AlertCategory.Exposure,prefix),ct);
                }
                _cursors[node]=page.NextAfter??0;
                await _alerts.ApplyAsync(new(node.NodeId,node.LedgerId,DateTimeOffset.UtcNow,[],true,AlertCategory.Exposure,"runtime:"),ct);
            }
            Status=Status with{LastEvaluationUtc=DateTimeOffset.UtcNow};
        }finally{_gate.Release();}
    }
}
