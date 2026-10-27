using Mrbr.Bastion.Inventory.Contracts;
using static Mrbr.Bastion.Vulnerabilities.Sqlite.VulnerabilityDatabase;

namespace Mrbr.Bastion.Vulnerabilities.Sqlite;

public sealed record FetchProgress(int Revision,int NextIndex,int? Total,DateTimeOffset NextAttemptUtc);
/// <summary>Reviewed mapping revisions, resumable NVD refreshes, published snapshots and exposure transitions.</summary>
public sealed class SqliteExposureStore : IExposureReader,IMappingReviewer,ICveEvidenceReader,IAsyncDisposable
{
    private readonly VulnerabilityDatabase _db;private readonly int _capacity;
    private SqliteExposureStore(VulnerabilityDatabase db,int capacity){_db=db;_capacity=capacity;}
    public static SqliteExposureStore Open(string path,int maximumFindings=100000)
    {
        if(maximumFindings is <1 or >1000000)throw new ArgumentOutOfRangeException(nameof(maximumFindings));
        return new(VulnerabilityDatabase.Open(path,"exposure","""
            CREATE TABLE mappings(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,document TEXT NOT NULL);
            CREATE TABLE mapping_history(id TEXT NOT NULL,revision INTEGER NOT NULL,document TEXT NOT NULL,PRIMARY KEY(id,revision));
            CREATE TABLE cache_heads(mapping TEXT PRIMARY KEY,revision INTEGER NOT NULL,fetched TEXT,error TEXT,complete INTEGER NOT NULL);
            CREATE TABLE cves(mapping TEXT NOT NULL,id TEXT NOT NULL,document TEXT NOT NULL,PRIMARY KEY(mapping,id));
            CREATE TABLE fetch_heads(mapping TEXT PRIMARY KEY,revision INTEGER NOT NULL,next_index INTEGER NOT NULL,total INTEGER,next_attempt TEXT NOT NULL);
            CREATE TABLE staged(mapping TEXT NOT NULL,id TEXT NOT NULL,document TEXT NOT NULL,PRIMARY KEY(mapping,id));
            CREATE TABLE findings(id TEXT PRIMARY KEY,node TEXT NOT NULL,ledger TEXT NOT NULL,item TEXT NOT NULL,document TEXT NOT NULL,digest TEXT NOT NULL);
            CREATE INDEX finding_item ON findings(node,ledger,item);
            CREATE TABLE finding_history(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL,document TEXT NOT NULL);
            CREATE INDEX finding_events ON finding_history(id,sequence DESC);
            """),maximumFindings);
    }
    public Task ReviewAsync(ProductMapping mapping,CancellationToken cancellationToken=default)
    {
        MappingValidation.Validate(mapping);return _db.Run((c,t)=>
        {
            string document=Encode(mapping);using(var q=Command(c,t,"SELECT revision,document FROM mappings WHERE id=$id",("$id",mapping.Id)))using(var r=q.ExecuteReader())
            {if(r.Read()){if(r.GetString(1)==document)return 0;if(mapping.Revision!=r.GetInt32(0)+1)throw new ArgumentException("Mapping review must advance the current revision by one.");}else if(mapping.Revision!=1)throw new ArgumentException("New mappings start at revision one.");}
            using(var q=Command(c,t,"SELECT COUNT(*) FROM mapping_history"))if(Convert.ToInt64(q.ExecuteScalar())>=10000)throw new IOException("Mapping history capacity reached.");
            using(var q=Command(c,t,"SELECT COUNT(*) FROM mappings"))if(Convert.ToInt64(q.ExecuteScalar())>=1000){using var exists=Command(c,t,"SELECT 1 FROM mappings WHERE id=$id",("$id",mapping.Id));if(exists.ExecuteScalar()is null)throw new IOException("Mapping capacity reached.");}
            Exec(c,t,"INSERT INTO mapping_history VALUES($id,$revision,$doc)",("$id",mapping.Id),("$revision",mapping.Revision),("$doc",document));
            Exec(c,t,"INSERT INTO mappings VALUES($id,$revision,$doc) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,document=excluded.document",("$id",mapping.Id),("$revision",mapping.Revision),("$doc",document));
            Exec(c,t,"DELETE FROM staged WHERE mapping=$id;DELETE FROM fetch_heads WHERE mapping=$id;",("$id",mapping.Id));
            Exec(c,t,"INSERT INTO cache_heads VALUES($id,$revision,NULL,'MappingChanged',0) ON CONFLICT(mapping) DO UPDATE SET revision=excluded.revision,error='MappingChanged',complete=0",("$id",mapping.Id),("$revision",mapping.Revision));return 0;
        },cancellationToken);
    }
    public Task<ProductMapping[]> ReadMappingsAsync(CancellationToken cancellationToken=default)=>_db.Run((c,t)=>{using var q=Command(c,t,"SELECT document FROM mappings ORDER BY id");using var r=q.ExecuteReader();var list=new List<ProductMapping>();while(r.Read())list.Add(Decode<ProductMapping>(r.GetString(0)));return list.ToArray();},cancellationToken);
    public Task<ProductMapping[]> ReadMappingHistoryAsync(string id,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>{using var q=Command(c,t,"SELECT document FROM mapping_history WHERE id=$id ORDER BY revision DESC LIMIT 100",("$id",id));using var r=q.ExecuteReader();var list=new List<ProductMapping>();while(r.Read())list.Add(Decode<ProductMapping>(r.GetString(0)));return list.ToArray();},cancellationToken);
    public Task<FetchProgress?> ReadProgressAsync(string id,CancellationToken ct=default)=>_db.Run((c,t)=>{using var q=Command(c,t,"SELECT revision,next_index,total,next_attempt FROM fetch_heads WHERE mapping=$id",("$id",id));using var r=q.ExecuteReader();return r.Read()?new FetchProgress(r.GetInt32(0),r.GetInt32(1),r.IsDBNull(2)?null:r.GetInt32(2),DateTimeOffset.Parse(r.GetString(3),System.Globalization.CultureInfo.InvariantCulture)):null;},ct);
    public Task StorePageAsync(ProductMapping mapping,int start,CveRecord[] records,int total,DateTimeOffset now,TimeSpan refreshInterval,CancellationToken ct=default)=>_db.Run((c,t)=>
    {
        if(start<0||total is <0 or >20000||records.Length>200||start+records.Length>total||records.Length==0&&start<total)throw new InvalidDataException("Incomplete or oversized intelligence page.");
        using(var q=Command(c,t,"SELECT revision FROM mappings WHERE id=$id",("$id",mapping.Id)))if(Convert.ToInt32(q.ExecuteScalar())!=mapping.Revision)throw new InvalidOperationException("Mapping changed during fetch.");
        using(var q=Command(c,t,"SELECT revision,next_index,total FROM fetch_heads WHERE mapping=$id",("$id",mapping.Id)))using(var r=q.ExecuteReader())
        {if(r.Read()){if(r.GetInt32(0)!=mapping.Revision||r.GetInt32(1)!=start||!r.IsDBNull(2)&&r.GetInt32(2)!=total)throw new InvalidDataException("Intelligence page sequence or total changed.");}else if(start!=0)throw new InvalidDataException("Intelligence fetch must begin at zero.");}
        using(var q=Command(c,t,"SELECT COUNT(*) FROM staged"))if(Convert.ToInt64(q.ExecuteScalar())+records.Length>100000)throw new IOException("Intelligence staging capacity reached.");
        foreach(var record in records)
        {string doc=Encode(record);if(doc.Length>262144)throw new InvalidDataException("CVE record budget exceeded.");Exec(c,t,"INSERT INTO staged VALUES($mapping,$id,$doc)",("$mapping",mapping.Id),("$id",record.Id),("$doc",doc));}
        int next=start+records.Length;bool complete=next==total;
        if(complete)
        {
            using(var q=Command(c,t,"SELECT COUNT(*) FROM cves WHERE mapping<>$id",("$id",mapping.Id)))if(Convert.ToInt64(q.ExecuteScalar())+total>100000)throw new IOException("Intelligence cache capacity reached.");
            Exec(c,t,"DELETE FROM cves WHERE mapping=$id;INSERT INTO cves SELECT mapping,id,document FROM staged WHERE mapping=$id;DELETE FROM staged WHERE mapping=$id;",("$id",mapping.Id));
            Exec(c,t,"INSERT INTO cache_heads VALUES($id,$revision,$now,NULL,1) ON CONFLICT(mapping) DO UPDATE SET revision=excluded.revision,fetched=excluded.fetched,error=NULL,complete=1",("$id",mapping.Id),("$revision",mapping.Revision),("$now",now.ToString("O")));
        }
        Exec(c,t,"INSERT INTO fetch_heads VALUES($id,$revision,$next,$total,$attempt) ON CONFLICT(mapping) DO UPDATE SET revision=excluded.revision,next_index=excluded.next_index,total=excluded.total,next_attempt=excluded.next_attempt",("$id",mapping.Id),("$revision",mapping.Revision),("$next",complete?0:next),("$total",complete?null:total),("$attempt",(complete?now+refreshInterval:now).ToString("O")));return 0;
    },ct);
    public Task FailRefreshAsync(ProductMapping mapping,DateTimeOffset now,CancellationToken ct=default)=>_db.Run((c,t)=>
    {
        Exec(c,t,"DELETE FROM staged WHERE mapping=$id",("$id",mapping.Id));
        Exec(c,t,"INSERT INTO cache_heads VALUES($id,$revision,NULL,'RefreshFailed',0) ON CONFLICT(mapping) DO UPDATE SET error='RefreshFailed'",("$id",mapping.Id),("$revision",mapping.Revision));
        Exec(c,t,"INSERT INTO fetch_heads VALUES($id,$revision,0,NULL,$attempt) ON CONFLICT(mapping) DO UPDATE SET next_index=0,total=NULL,next_attempt=excluded.next_attempt,revision=excluded.revision",("$id",mapping.Id),("$revision",mapping.Revision),("$attempt",now.AddMinutes(5).ToString("O")));return 0;
    },ct);
    public Task<IntelligenceSnapshot> ReadSnapshotAsync(ProductMapping mapping,CancellationToken ct=default)=>_db.Run((c,t)=>
    {
        DateTimeOffset? fetched=null;string? error=null;bool complete=false;
        using(var q=Command(c,t,"SELECT revision,fetched,error,complete FROM cache_heads WHERE mapping=$id",("$id",mapping.Id)))using(var r=q.ExecuteReader())if(r.Read()){fetched=r.IsDBNull(1)?null:DateTimeOffset.Parse(r.GetString(1),System.Globalization.CultureInfo.InvariantCulture);error=r.GetInt32(0)!=mapping.Revision?"MappingChanged":r.IsDBNull(2)?null:r.GetString(2);complete=r.GetBoolean(3)&&r.GetInt32(0)==mapping.Revision;}
        using var rows=Command(c,t,"SELECT document FROM cves WHERE mapping=$id ORDER BY id",("$id",mapping.Id));using var reader=rows.ExecuteReader();var records=new List<CveRecord>();while(reader.Read())records.Add(Decode<CveRecord>(reader.GetString(0)));return new IntelligenceSnapshot(mapping.Id,fetched,error,complete,records.ToArray());
    },ct);
    public Task SaveAsync(ExposureFinding finding,CancellationToken ct=default)=>_db.Run((c,t)=>
    {
        using(var first=Command(c,t,"SELECT document FROM findings WHERE id=$id",("$id",finding.Id)))
            finding=finding with{FirstDetectedUtc=first.ExecuteScalar() is string old?Decode<ExposureFinding>(old).FirstDetectedUtc??finding.EvaluatedUtc:finding.EvaluatedUtc};
        string doc=Encode(finding),digest=InventoryJson.Hash(Encode(finding with{EvaluatedUtc=default,ObservedUtc=default,IntelligenceUtc=null}));string? previous=null;
        using(var q=Command(c,t,"SELECT digest FROM findings WHERE id=$id",("$id",finding.Id)))previous=q.ExecuteScalar()as string;
        if(previous==digest){Exec(c,t,"UPDATE findings SET document=$doc WHERE id=$id",("$id",finding.Id),("$doc",doc));return 0;}
        if(previous is null){using var count=Command(c,t,"SELECT COUNT(*) FROM findings");if(Convert.ToInt64(count.ExecuteScalar())>=_capacity)throw new IOException("Exposure capacity reached.");}
        using(var count=Command(c,t,"SELECT COUNT(*) FROM finding_history"))if(Convert.ToInt64(count.ExecuteScalar())>=_capacity*10L)throw new IOException("Exposure history capacity reached.");
        Exec(c,t,"INSERT INTO findings VALUES($id,$node,$ledger,$item,$doc,$digest) ON CONFLICT(id) DO UPDATE SET document=excluded.document,digest=excluded.digest",("$id",finding.Id),("$node",finding.NodeId),("$ledger",finding.LedgerId.ToString("D")),("$item",finding.ItemKey),("$doc",doc),("$digest",digest));
        Exec(c,t,"INSERT INTO finding_history(id,document) VALUES($id,$doc)",("$id",finding.Id),("$doc",doc));return 0;
    },ct);
    public Task<ExposureFinding[]> ReadItemAsync(string node,Guid ledger,string item,CancellationToken ct=default)=>_db.Run((c,t)=>{using var q=Command(c,t,"SELECT document FROM findings WHERE node=$node AND ledger=$ledger AND item=$item ORDER BY id",("$node",node),("$ledger",ledger.ToString("D")),("$item",item));using var r=q.ExecuteReader();var rows=new List<ExposureFinding>();while(r.Read())rows.Add(Decode<ExposureFinding>(r.GetString(0)));return rows.ToArray();},ct);
    public Task<ExposurePage> ReadFindingsAsync(string node,Guid ledger,string? after=null,int limit=100,CancellationToken cancellationToken=default)
    {
        if(limit is <1 or >100||after?.Length>64)throw new ArgumentException("Invalid exposure page.");return _db.Run((c,t)=>{using var q=Command(c,t,"SELECT document FROM findings WHERE node=$node AND ledger=$ledger AND id>$after ORDER BY id LIMIT $limit",("$node",node),("$ledger",ledger.ToString("D")),("$after",after??""),("$limit",limit+1));using var r=q.ExecuteReader();var rows=new List<ExposureFinding>();while(r.Read())rows.Add(Decode<ExposureFinding>(r.GetString(0)));bool more=rows.Count>limit;if(more)rows.RemoveAt(rows.Count-1);return new ExposurePage(rows.ToArray(),more?rows[^1].Id:null);},cancellationToken);
    }
    public Task<ExposureFinding[]> ReadHistoryAsync(string findingId,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>{using var q=Command(c,t,"SELECT document FROM finding_history WHERE id=$id ORDER BY sequence DESC LIMIT 100",("$id",findingId));using var r=q.ExecuteReader();var rows=new List<ExposureFinding>();while(r.Read())rows.Add(Decode<ExposureFinding>(r.GetString(0)));return rows.ToArray();},cancellationToken);
    public ValueTask DisposeAsync()=>_db.DisposeAsync();
    public Task<CveEvidence?> ReadCveAsync(string mappingId,string cveId,CancellationToken cancellationToken=default)
    {
        if(mappingId.Length>64||cveId.Length>32)throw new ArgumentException("Invalid intelligence identity.");
        return _db.Run((c,t)=>
        {
            using var q=Command(c,t,"SELECT h.revision,h.fetched,h.complete,h.error,c.document FROM cves c JOIN cache_heads h ON h.mapping=c.mapping WHERE c.mapping=$mapping AND c.id=$id",("$mapping",mappingId),("$id",cveId));using var r=q.ExecuteReader();
            return r.Read()?new CveEvidence(mappingId,r.GetInt32(0),r.IsDBNull(1)?null:DateTimeOffset.Parse(r.GetString(1),System.Globalization.CultureInfo.InvariantCulture),r.GetBoolean(2),r.IsDBNull(3)?null:r.GetString(3),Decode<CveRecord>(r.GetString(4))):null;
        },cancellationToken);
    }
}
