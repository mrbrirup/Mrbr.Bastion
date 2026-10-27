using Mrbr.Bastion.Inventory.Contracts;
using static Mrbr.Bastion.Inventory.Sqlite.InventoryDatabase;

namespace Mrbr.Bastion.Inventory.Sqlite;

public sealed class SqliteCrawlerJournal : ICrawlerJournal,IAsyncDisposable
{
    private readonly InventoryDatabase _db;
    private SqliteCrawlerJournal(InventoryDatabase db)=>_db=db;
    public static SqliteCrawlerJournal Open(string path)=>new(InventoryDatabase.Open(path,"crawler","""
        CREATE TABLE tasks(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,scan TEXT NOT NULL,started INTEGER NOT NULL,finished INTEGER NOT NULL,partial INTEGER NOT NULL);
        CREATE TABLE work(id INTEGER PRIMARY KEY AUTOINCREMENT,task TEXT NOT NULL REFERENCES tasks(id),path TEXT NOT NULL,done INTEGER NOT NULL,UNIQUE(task,path));
        """));
    public Task<CrawlerState> InitializeAsync(CrawlerTask task,CancellationToken cancellationToken=default)
    {
        task.Validate();return _db.Run((c,t)=>{using(var q=Command(c,t,"SELECT fingerprint FROM tasks WHERE id=$id",("$id",task.Id)))if(q.ExecuteScalar() is string fp&&fp!=task.Fingerprint)throw new InvalidDataException("Crawler configuration changed; use a new task ID and checkpoint scope.");
            Exec(c,t,"INSERT OR IGNORE INTO tasks VALUES($id,$fp,$scan,0,0,0)",("$id",task.Id),("$fp",task.Fingerprint),("$scan",Guid.NewGuid().ToString("D")));
            Exec(c,t,"INSERT OR IGNORE INTO work(task,path,done) VALUES($id,$root,0)",("$id",task.Id),("$root",Path.GetFullPath(task.Root)));return State(c,t,task.Id);},cancellationToken);
    }
    private static CrawlerState State(Microsoft.Data.Sqlite.SqliteConnection c,Microsoft.Data.Sqlite.SqliteTransaction t,string id)
    {using var q=Command(c,t,"SELECT fingerprint,scan,started,finished,partial,(SELECT COUNT(*) FROM work WHERE task=$id AND done=0),(SELECT COUNT(*) FROM work WHERE task=$id AND done=1) FROM tasks WHERE id=$id",("$id",id));using var r=q.ExecuteReader();if(!r.Read())throw new KeyNotFoundException();return new(id,r.GetString(0),Guid.Parse(r.GetString(1)),r.GetBoolean(2),r.GetBoolean(3),r.GetBoolean(4),r.GetInt64(5),r.GetInt64(6));}
    public Task<CrawlerState> StateAsync(string taskId,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>State(c,t,taskId),cancellationToken);
    public Task MarkStartedAsync(string taskId,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>{Exec(c,t,"UPDATE tasks SET started=1 WHERE id=$id",("$id",taskId));return 0;},cancellationToken);
    public Task<CrawlerWork?> NextAsync(string taskId,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>{using var q=Command(c,t,"SELECT id,path FROM work WHERE task=$id AND done=0 ORDER BY id LIMIT 1",("$id",taskId));using var r=q.ExecuteReader();return r.Read()?new CrawlerWork(r.GetInt64(0),r.GetString(1)):null;},cancellationToken);
    public Task EnqueueAsync(string taskId,string path,int maximum,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>
    {using(var q=Command(c,t,"SELECT COUNT(*) FROM work WHERE task=$id",("$id",taskId)))if(Convert.ToInt64(q.ExecuteScalar())>=maximum){using var exists=Command(c,t,"SELECT 1 FROM work WHERE task=$id AND path=$path",("$id",taskId),("$path",path));if(exists.ExecuteScalar() is null)throw new IOException("CrawlerWorkBudgetExceeded");}
        Exec(c,t,"INSERT OR IGNORE INTO work(task,path,done) VALUES($id,$path,0)",("$id",taskId),("$path",path));return 0;},cancellationToken);
    public Task FinishWorkAsync(string taskId,long id,bool partial,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>{Exec(c,t,"UPDATE work SET done=1 WHERE id=$work AND task=$id",("$work",id),("$id",taskId));if(partial)Exec(c,t,"UPDATE tasks SET partial=1 WHERE id=$id",("$id",taskId));return 0;},cancellationToken);
    public Task FinishAsync(string taskId,CancellationToken cancellationToken=default)=>_db.Run((c,t)=>{if(State(c,t,taskId).Pending!=0)throw new InvalidOperationException("Crawler still has pending work.");Exec(c,t,"UPDATE tasks SET finished=1 WHERE id=$id",("$id",taskId));return 0;},cancellationToken);
    public ValueTask DisposeAsync()=>_db.DisposeAsync();
    public Task RestartCompletedAsync(CrawlerTask task,CancellationToken cancellationToken=default)
    {
        task.Validate();return _db.Run((c,t)=>
        {
            var state=State(c,t,task.Id);if(!state.Finished||state.Fingerprint!=task.Fingerprint)throw new InvalidOperationException("Only a completed crawler with unchanged scope can start a new scan.");
            Exec(c,t,"DELETE FROM work WHERE task=$id;UPDATE tasks SET scan=$scan,started=0,finished=0,partial=0 WHERE id=$id;INSERT INTO work(task,path,done) VALUES($id,$root,0)",("$id",task.Id),("$scan",Guid.NewGuid().ToString("D")),("$root",Path.GetFullPath(task.Root)));return 0;
        },cancellationToken);
    }
}
