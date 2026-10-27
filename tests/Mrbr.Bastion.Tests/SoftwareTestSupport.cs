using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Ingestion;
using Mrbr.Bastion.Ingestion.Sqlite;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Vulnerabilities;

namespace Mrbr.Bastion.Tests;

internal sealed class SoftwareFixture : IAsyncDisposable
{
    public TestLedger Local{get;}=new();
    public DurableTelemetryCache Cache{get;private set;}=null!;
    public SqliteIngestionStore Ledger{get;private set;}=null!;
    public SqliteInventoryStore Inventory{get;private set;}=null!;
    public StaticNodeTrustStore Trust{get;private set;}=null!;
    public TelemetryIngestionService Service{get;private set;}=null!;
    public string Node=>Local.Options.NodeId;
    public Guid LedgerId{get;private set;}
    public string PathFor(string name)=>Path.Combine(Local.DirectoryPath,name);
    public static async Task<SoftwareFixture> CreateAsync(int maximum=100000)
    {
        var f=new SoftwareFixture();try
        {
            f.Cache=await DurableTelemetryCache.OpenAsync(f.Local.Options with{AdditionalPayloadCodecs=[new InventoryPayloadCodec()]},f.Local.Node,f.Local.Node,f.Local.Server);
            f.LedgerId=(await f.Cache.GetStatusAsync()).Checkpoint.LedgerId;f.Trust=new([new(f.Node,f.LedgerId,f.Local.Node)]);
            f.Ledger=await SqliteIngestionStore.OpenAsync(new(){DatabasePath=f.PathFor("ingestion.db"),BlockLimits=new(){AdditionalPayloadCodecs=[new InventoryPayloadCodec()]}},f.Trust,f.Local.Server);
            f.Service=new(f.Trust,f.Ledger,f.Local.Server,f.Local.Server,new(){AdditionalPayloadCodecs=[new InventoryPayloadCodec()]});
            f.Inventory=SqliteInventoryStore.Open(f.PathFor("inventory.db"),maximum);return f;
        }catch{await f.DisposeAsync();throw;}
    }
    public async Task<SignedTelemetryBlock> AppendAsync(params InventoryRecord[] rows)
    {var block=await Cache.AppendPayloadAsync(LedgerProtocol.InventoryPayloadFormat,InventoryJson.Encode(rows),rows.Length);var receipt=await Service.IngestAsync(block);await Cache.ReconcileAsync(receipt);return block;}
    public static InventoryRecord Record(InventoryRecordKind kind=InventoryRecordKind.Software,Guid? scan=null,SoftwareArtifact? artifact=null,bool complete=false,InventorySource source=InventorySource.FileSystem)=>
        new(1,Guid.NewGuid(),scan??Guid.NewGuid(),"fixture",source,kind,DateTimeOffset.UtcNow,"fixture-root",artifact??(kind==InventoryRecordKind.Software?new("fixture.exe",Publisher:"Vendor",Product:"Widget",ProductVersion:"1.2.0"):null),kind==InventoryRecordKind.Coverage?new("AccessDenied","denied-path"):null,complete);
    public async ValueTask DisposeAsync(){if(Inventory is not null)await Inventory.DisposeAsync();if(Ledger is not null)await Ledger.DisposeAsync();if(Cache is not null)await Cache.DisposeAsync();Local.Dispose();}
}
internal static class SoftwareEvidence
{
    public const string Cpe="cpe:2.3:a:vendor:widget:*:*:*:*:*:*:*:*";
    public static ProductMapping Mapping(int revision=1)=>new("widget",revision,"Vendor","Widget",Cpe,VersionScheme.Numeric,VersionEvidence.ProductVersion,"fixture-reviewer",DateTimeOffset.UtcNow);
    public static CveRecord Cve(string id="CVE-2026-12345",string? start="1.0.0",string? end="2.0.0")=>new(id,"Analyzed","Fixture advisory","https://nvd.nist.gov/vuln/detail/"+id,DateTimeOffset.UtcNow,9.1,[new("OR",false,[new(Cpe,true,StartIncluding:start,EndExcluding:end)],[])]);
    public static InventoryItem Item(SoftwareArtifact? artifact=null)=>new(1,"node",Guid.NewGuid(),"item",SoftwareFixture.Record(artifact:artifact),DateTimeOffset.UtcNow);
}
