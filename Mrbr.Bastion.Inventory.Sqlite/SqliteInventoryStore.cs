using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Inventory.Contracts;
using static Mrbr.Bastion.Inventory.Sqlite.InventoryDatabase;

namespace Mrbr.Bastion.Inventory.Sqlite;

public sealed class SqliteInventoryStore : IInventoryReader,IAsyncDisposable
{
    private readonly InventoryDatabase _db;private readonly int _maximum;
    private SqliteInventoryStore(InventoryDatabase db,int maximum){_db=db;_maximum=maximum;}
    public static SqliteInventoryStore Open(string path,int maximumItems=100000)
    {
        if(maximumItems is <1 or >1000000)throw new ArgumentOutOfRangeException(nameof(maximumItems));
        return new(InventoryDatabase.Open(path,"central","""
            CREATE TABLE heads(node TEXT NOT NULL,ledger TEXT NOT NULL,sequence INTEGER NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(node,ledger));
            CREATE TABLE items(id INTEGER PRIMARY KEY AUTOINCREMENT,node TEXT NOT NULL,ledger TEXT NOT NULL,item_key TEXT NOT NULL,source INTEGER NOT NULL,task TEXT NOT NULL,scope TEXT NOT NULL,scan TEXT NOT NULL,record TEXT NOT NULL,received TEXT NOT NULL,missing INTEGER NOT NULL,missing_utc TEXT,UNIQUE(node,ledger,item_key));
            CREATE INDEX item_scan ON items(node,ledger,task,scope,scan);
            CREATE TABLE scans(node TEXT NOT NULL,ledger TEXT NOT NULL,scan TEXT NOT NULL,task TEXT NOT NULL,source INTEGER NOT NULL,scope TEXT NOT NULL,received TEXT NOT NULL,finished INTEGER NOT NULL,complete INTEGER NOT NULL,coverage INTEGER NOT NULL,pending INTEGER NOT NULL,completed INTEGER NOT NULL,started_observed TEXT NOT NULL,PRIMARY KEY(node,ledger,scan,task,source,scope));
            CREATE TABLE record_ids(node TEXT NOT NULL,ledger TEXT NOT NULL,id TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(node,ledger,id));
            CREATE TABLE coverage(id INTEGER PRIMARY KEY AUTOINCREMENT,node TEXT NOT NULL,ledger TEXT NOT NULL,scan TEXT NOT NULL,document TEXT NOT NULL);
            """),maximumItems);
    }
    public Task<LedgerCheckpoint> CheckpointAsync(string node,Guid ledger,CancellationToken ct=default)=>_db.Run((c,t)=>
    {using var q=Command(c,t,"SELECT sequence,hash FROM heads WHERE node=$node AND ledger=$ledger",("$node",node),("$ledger",ledger.ToString("D")));using var r=q.ExecuteReader();return r.Read()?new LedgerCheckpoint(node,ledger,r.GetInt64(0),r.GetString(1)):new(node,ledger,0,LedgerProtocol.GenesisHash);},ct);
    public Task ApplyAsync(SignedTelemetryBlock block,DateTimeOffset accepted,CancellationToken ct=default)=>_db.Run((c,t)=>
    {
        var b=block.Content;string ledger=b.LedgerId.ToString("D");long last=0;string hash=LedgerProtocol.GenesisHash;
        using(var q=Command(c,t,"SELECT sequence,hash FROM heads WHERE node=$node AND ledger=$ledger",("$node",b.NodeId),("$ledger",ledger)))using(var r=q.ExecuteReader())if(r.Read()){last=r.GetInt64(0);hash=r.GetString(1);}
        if(last==b.SequenceNumber&&hash==block.BlockHash)return 0;
        if(b.SequenceNumber!=last+1||b.PreviousBlockHash!=hash)throw new InvalidDataException("Inventory projection cursor conflicts with retained ledger evidence.");
        var rows=b.PayloadFormat==LedgerProtocol.InventoryPayloadFormat?InventoryJson.Decode(b.Payload):[];
        foreach(var row in rows)
        {
            ct.ThrowIfCancellationRequested();string json=Encode(row),digest=InventoryJson.Hash(json);
            using(var q=Command(c,t,"SELECT hash FROM record_ids WHERE node=$n AND ledger=$l AND id=$id",("$n",b.NodeId),("$l",ledger),("$id",row.Id.ToString("D"))))
            {if(q.ExecuteScalar() is string old){if(old!=digest)throw new InvalidDataException("Inventory record identity was reused with different content.");continue;}}
            using(var count=Command(c,t,"SELECT COUNT(*) FROM record_ids"))if(Convert.ToInt64(count.ExecuteScalar())>=_maximum*20L)throw new IOException("Inventory history capacity reached.");
            Exec(c,t,"INSERT INTO record_ids VALUES($n,$l,$id,$hash)",("$n",b.NodeId),("$l",ledger),("$id",row.Id.ToString("D")),("$hash",digest));
            Exec(c,t,"INSERT OR IGNORE INTO scans VALUES($n,$l,$scan,$task,$source,$scope,$received,0,0,0,0,0,$observed)",("$observed",row.ObservedUtc.ToString("O")),("$n",b.NodeId),("$l",ledger),("$scan",row.ScanId.ToString("D")),("$task",row.TaskId),("$source",(int)row.Source),("$scope",row.Scope),("$received",accepted.ToString("O")));
            if(row.Progress is {} progress)Exec(c,t,"UPDATE scans SET pending=$pending,completed=$done,received=$received WHERE node=$n AND ledger=$l AND scan=$scan AND task=$task AND source=$source AND scope=$scope",("$pending",progress.Pending),("$done",progress.Completed),("$received",accepted.ToString("O")),("$n",b.NodeId),("$l",ledger),("$scan",row.ScanId.ToString("D")),("$task",row.TaskId),("$source",(int)row.Source),("$scope",row.Scope));
            if(row.Artifact is not null)
            {
                string key=InventoryJson.ItemKey(row);using(var count=Command(c,t,"SELECT COUNT(*) FROM items"))
                if(Convert.ToInt64(count.ExecuteScalar())>=_maximum){using var exists=Command(c,t,"SELECT 1 FROM items WHERE node=$n AND ledger=$l AND item_key=$key",("$n",b.NodeId),("$l",ledger),("$key",key));if(exists.ExecuteScalar() is null)throw new IOException("Inventory item capacity reached.");}
                var stored=row;
                if(row.Kind==InventoryRecordKind.ProcessStopped)
                {using var old=Command(c,t,"SELECT record FROM items WHERE node=$n AND ledger=$l AND item_key=$key",("$n",b.NodeId),("$l",ledger),("$key",key));if(old.ExecuteScalar() is string value){var previous=Decode<InventoryRecord>(value);stored=row with{Artifact=previous.Artifact! with{ReportedRunning=false}};}}
                Exec(c,t,"""
                    INSERT INTO items(node,ledger,item_key,source,task,scope,scan,record,received,missing) VALUES($n,$l,$key,$source,$task,$scope,$scan,$json,$received,0)
                    ON CONFLICT(node,ledger,item_key) DO UPDATE SET scan=excluded.scan,record=excluded.record,received=excluded.received,missing=0,missing_utc=NULL
                    """,("$n",b.NodeId),("$l",ledger),("$key",key),("$source",(int)row.Source),("$task",row.TaskId),("$scope",row.Scope),("$scan",row.ScanId.ToString("D")),("$json",Encode(stored)),("$received",accepted.ToString("O")));
            }
            if(row.Kind==InventoryRecordKind.Coverage)
            {
                Exec(c,t,"UPDATE scans SET coverage=coverage+1 WHERE node=$n AND ledger=$l AND scan=$scan AND task=$task AND source=$source AND scope=$scope",("$n",b.NodeId),("$l",ledger),("$scan",row.ScanId.ToString("D")),("$task",row.TaskId),("$source",(int)row.Source),("$scope",row.Scope));
                Exec(c,t,"INSERT INTO coverage(node,ledger,scan,document) VALUES($n,$l,$scan,$doc)",("$n",b.NodeId),("$l",ledger),("$scan",row.ScanId.ToString("D")),("$doc",json));
            }
            if(row.Kind==InventoryRecordKind.ScanCompleted)
            {
                using var coverage=Command(c,t,"SELECT COALESCE(SUM(coverage),0) FROM scans WHERE node=$n AND ledger=$l AND scan=$scan AND task=$task AND scope=$scope",("$n",b.NodeId),("$l",ledger),("$scan",row.ScanId.ToString("D")),("$task",row.TaskId),("$scope",row.Scope));
                bool complete=row.Complete&&Convert.ToInt64(coverage.ExecuteScalar())==0;
                Exec(c,t,"UPDATE scans SET finished=1,complete=$complete,received=$received WHERE node=$n AND ledger=$l AND scan=$scan AND task=$task AND (source=$source OR ($source=2 AND source=3)) AND scope=$scope",("$complete",complete),("$received",accepted.ToString("O")),("$n",b.NodeId),("$l",ledger),("$scan",row.ScanId.ToString("D")),("$task",row.TaskId),("$source",(int)row.Source),("$scope",row.Scope));
                // Absence is no fresher than the beginning of the scan, even after an offline backlog or long resume.
                if(complete)Exec(c,t,"UPDATE items SET missing=1,missing_utc=(SELECT started_observed FROM scans WHERE node=$n AND ledger=$l AND scan=$scan AND task=$task AND scope=$scope AND source=$source) WHERE node=$n AND ledger=$l AND task=$task AND scope=$scope AND scan<>$scan AND (source=$source OR ($source=2 AND source=3))",("$n",b.NodeId),("$l",ledger),("$task",row.TaskId),("$scope",row.Scope),("$scan",row.ScanId.ToString("D")),("$source",(int)row.Source));
            }
        }
        Exec(c,t,"INSERT INTO heads VALUES($n,$l,$seq,$hash) ON CONFLICT(node,ledger) DO UPDATE SET sequence=excluded.sequence,hash=excluded.hash",("$n",b.NodeId),("$l",ledger),("$seq",b.SequenceNumber),("$hash",block.BlockHash));return 0;
    },ct);
    public Task<InventoryPage> ReadAsync(string nodeId,Guid ledgerId,long after=0,int limit=100,string? search=null,CancellationToken cancellationToken=default)
    {
        if(after<0||limit is <1 or >100||search?.Length>256)throw new ArgumentException("Invalid inventory query.");
        return _db.Run((c,t)=>{using var q=Command(c,t,"SELECT id,item_key,record,received,missing,missing_utc FROM items WHERE node=$n AND ledger=$l AND id>$after AND ($search IS NULL OR instr(lower(record),lower($search))>0) ORDER BY id LIMIT $limit",("$n",nodeId),("$l",ledgerId.ToString("D")),("$after",after),("$search",search),("$limit",limit+1));using var r=q.ExecuteReader();var items=new List<InventoryItem>();while(r.Read())items.Add(new(r.GetInt64(0),nodeId,ledgerId,r.GetString(1),Decode<InventoryRecord>(r.GetString(2)),DateTimeOffset.Parse(r.GetString(3),System.Globalization.CultureInfo.InvariantCulture),r.GetBoolean(4),r.IsDBNull(5)?null:DateTimeOffset.Parse(r.GetString(5),System.Globalization.CultureInfo.InvariantCulture)));bool more=items.Count>limit;if(more)items.RemoveAt(items.Count-1);return new InventoryPage(items.ToArray(),more?items[^1].Sequence:null);},cancellationToken);
    }
    public Task<InventoryScan[]> ReadScansAsync(string nodeId,Guid ledgerId,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>
    {
        using var q=Command(c,t,"SELECT scan,task,source,scope,received,finished,complete,coverage,(SELECT COUNT(*) FROM items i WHERE i.node=s.node AND i.ledger=s.ledger AND i.scan=s.scan AND i.task=s.task AND i.source=s.source AND i.scope=s.scope),pending,completed FROM scans s WHERE node=$n AND ledger=$l ORDER BY received DESC LIMIT 100",("$n",nodeId),("$l",ledgerId.ToString("D")));using var r=q.ExecuteReader();var rows=new List<InventoryScan>();while(r.Read())rows.Add(new(nodeId,ledgerId,Guid.Parse(r.GetString(0)),r.GetString(1),(InventorySource)r.GetInt32(2),r.GetString(3),DateTimeOffset.Parse(r.GetString(4),System.Globalization.CultureInfo.InvariantCulture),r.GetBoolean(5),r.GetBoolean(6),r.GetInt32(8),r.GetInt32(7),r.GetInt64(9),r.GetInt64(10)));return rows.ToArray();
    },cancellationToken);
    public ValueTask DisposeAsync()=>_db.DisposeAsync();
    public Task<InventoryRecord[]> ReadCoverageAsync(string nodeId,Guid ledgerId,Guid? scanId=null,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>
    {using var q=Command(c,t,"SELECT document FROM coverage WHERE node=$n AND ledger=$l AND ($scan IS NULL OR scan=$scan) ORDER BY id DESC LIMIT 100",("$n",nodeId),("$l",ledgerId.ToString("D")),("$scan",scanId?.ToString("D")));using var r=q.ExecuteReader();var rows=new List<InventoryRecord>();while(r.Read())rows.Add(Decode<InventoryRecord>(r.GetString(0)));return rows.ToArray();},cancellationToken);
}
