using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Mrbr.Bastion.Operators.Sqlite;

public sealed record SqliteOperatorOptions
{
    public required string DatabasePath{get;init;}
    public int MaximumUsers{get;init;}=10000;
    public int MaximumSecurityEvents{get;init;}=1000000;
    public int MaximumSessions{get;init;}=50000;
}
/// <summary>Single-writer identity store. Security changes, revocation and their audit events commit together.</summary>
public sealed class SqliteOperatorStore:IOperatorStore
{
    private readonly SqliteConnection _db;private readonly FileStream _writer;private readonly SqliteOperatorOptions _options;
    private readonly SemaphoreSlim _gate=new(1,1);private bool _disposed;
    private SqliteOperatorStore(SqliteConnection db,FileStream writer,SqliteOperatorOptions options){_db=db;_writer=writer;_options=options;}
    public static SqliteOperatorStore Open(SqliteOperatorOptions options)
    {
        if(string.IsNullOrWhiteSpace(options.DatabasePath)||options.DatabasePath==":memory:"||options.MaximumUsers is <1 or >100000
            ||options.MaximumSecurityEvents is <1 or >10000000||options.MaximumSessions is <1 or >1000000)throw new ArgumentException("Invalid operator storage configuration.");
        string path=Path.GetFullPath(options.DatabasePath);Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var writer=new FileStream(path+".writer.lock",FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);SqliteConnection? db=null;
        try
        {
            bool exists=File.Exists(path);db=new(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false,Mode=exists?SqliteOpenMode.ReadWrite:SqliteOpenMode.ReadWriteCreate}.ToString());db.Open();
            using(var setup=Command(db,null,"PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA foreign_keys=ON;PRAGMA trusted_schema=OFF;"))setup.ExecuteNonQuery();
            if(!exists)
            {
                using var tx=db.BeginTransaction();using var create=Command(db,tx,"""
                    CREATE TABLE operator_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,role TEXT NOT NULL,last_ticks INTEGER NOT NULL);
                    INSERT INTO operator_metadata VALUES(1,1,'operators',0);
                    CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,display TEXT NOT NULL,roles TEXT NOT NULL,enabled INTEGER NOT NULL,
                        must_change INTEGER NOT NULL,revision INTEGER NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL,last_login INTEGER,
                        password_hash TEXT NOT NULL,stamp TEXT NOT NULL,failures INTEGER NOT NULL,locked_until INTEGER);
                    CREATE TABLE sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),stamp TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL);
                    CREATE INDEX user_sessions ON sessions(user_id);
                    CREATE TABLE security_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,occurred INTEGER NOT NULL,actor_id TEXT,actor TEXT NOT NULL,action TEXT NOT NULL,target_id TEXT,target TEXT,detail TEXT,remote TEXT);
                    """);create.ExecuteNonQuery();tx.Commit();
            }
            using(var check=Command(db,null,"PRAGMA quick_check"))if(check.ExecuteScalar()as string!="ok")throw new InvalidDataException("Operator database integrity check failed.");
            using(var check=Command(db,null,"SELECT version,role FROM operator_metadata WHERE singleton=1"))using(var r=check.ExecuteReader())if(!r.Read()||r.GetInt32(0)!=1||r.GetString(1)!="operators")throw new InvalidDataException("Unsupported operator database role/schema.");
            using(var check=Command(db,null,"PRAGMA foreign_key_check"))using(var r=check.ExecuteReader())if(r.Read())throw new InvalidDataException("Operator session references missing identity.");
            return new(db,writer,options);
        }catch{db?.Dispose();writer.Dispose();throw;}
    }
    private async Task<T> Run<T>(Func<SqliteTransaction,T> body,CancellationToken ct)
    {await _gate.WaitAsync(ct);try{ObjectDisposedException.ThrowIf(_disposed,this);using var tx=_db.BeginTransaction();var value=body(tx);ct.ThrowIfCancellationRequested();tx.Commit();return value;}finally{_gate.Release();}}
    private static SqliteCommand Command(SqliteConnection db,SqliteTransaction? tx,string sql,params(string,object?)[] values)
    {var q=db.CreateCommand();q.Transaction=tx;q.CommandText=sql;foreach(var(name,value)in values)q.Parameters.AddWithValue(name,value??DBNull.Value);return q;}
    private SqliteCommand Query(SqliteTransaction tx,string sql,params(string,object?)[] values)=>Command(_db,tx,sql,values);
    private void Execute(SqliteTransaction tx,string sql,params(string,object?)[] values){using var q=Query(tx,sql,values);q.ExecuteNonQuery();}
    private static DateTimeOffset Utc(long ticks)=>new(ticks,TimeSpan.Zero);
    private const string Columns="id,name,display,roles,enabled,must_change,revision,created,updated,last_login,password_hash,stamp,failures,locked_until";
    private static OperatorCredential Read(SqliteDataReader r)
    {
        var roles=JsonSerializer.Deserialize<OperatorRole[]>(r.GetString(3),OperatorValidation.Json)??throw new InvalidDataException("Missing operator roles.");OperatorValidation.Roles(roles);
        var account=new OperatorAccount(Guid.Parse(r.GetString(0)),r.GetString(1),r.GetString(2),roles,r.GetBoolean(4),r.GetBoolean(5),r.GetInt64(6),Utc(r.GetInt64(7)),Utc(r.GetInt64(8)),r.IsDBNull(9)?null:Utc(r.GetInt64(9)));
        return new(account,r.GetString(10),Guid.Parse(r.GetString(11)),r.GetInt32(12),r.IsDBNull(13)?null:Utc(r.GetInt64(13)));
    }
    private OperatorCredential? Find(SqliteTransaction tx,string where,object value)
    {using var q=Query(tx,$"SELECT {Columns} FROM users WHERE {where}=$value",("$value",value));using var r=q.ExecuteReader();return r.Read()?Read(r):null;}
    public Task<OperatorCredential?> FindCredentialsAsync(string normalizedName,CancellationToken ct=default)=>Run(tx=>Find(tx,"name",normalizedName),ct);
    public Task<OperatorCredential?> FindByIdAsync(Guid id,CancellationToken ct=default)=>Run(tx=>Find(tx,"id",id.ToString("D")),ct);
    private void Clock(SqliteTransaction tx,DateTimeOffset now)
    {
        if(now==default||now.Offset!=TimeSpan.Zero)throw new ArgumentException("Operator time must be UTC.");
        using(var q=Query(tx,"SELECT last_ticks FROM operator_metadata WHERE singleton=1"))if(Convert.ToInt64(q.ExecuteScalar())>now.UtcTicks)throw new InvalidDataException("Time moved behind retained operator history.");
        Execute(tx,"UPDATE operator_metadata SET last_ticks=$now WHERE singleton=1",("$now",now.UtcTicks));
    }
    private void Event(SqliteTransaction tx,DateTimeOffset now,OperatorAccount? actor,string action,OperatorAccount? target,string? detail=null,string? remote=null,string? anonymous=null)
    {
        using(var count=Query(tx,"SELECT COUNT(*) FROM security_events"))if(Convert.ToInt64(count.ExecuteScalar())>=_options.MaximumSecurityEvents)throw new IOException("Operator security history capacity reached.");
        Execute(tx,"INSERT INTO security_events(occurred,actor_id,actor,action,target_id,target,detail,remote) VALUES($now,$actorid,$actor,$action,$targetid,$target,$detail,$remote)",
            ("$now",now.UtcTicks),("$actorid",actor?.Id.ToString("D")),("$actor",actor?.UserName??anonymous??"local-provisioning"),("$action",action),
            ("$targetid",target?.Id.ToString("D")),("$target",target?.UserName),("$detail",detail),("$remote",remote));
    }
    private OperatorCredential RequireActor(SqliteTransaction tx,OperatorActor actor,bool admin)
    {
        var user=Find(tx,"id",actor.UserId.ToString("D"));
        if(user is null||!user.Account.Enabled||user.SecurityStamp!=actor.SecurityStamp||admin&&(user.Account.MustChangePassword||!user.Account.Roles.Contains(OperatorRole.Administrator)))throw new OperatorAccessException();
        return user;
    }
    private OperatorCredential RequireTarget(SqliteTransaction tx,Guid id,long revision)
    {var target=Find(tx,"id",id.ToString("D"))??throw new KeyNotFoundException();if(target.Account.Revision!=revision)throw new OperatorConflictException("OperatorRevisionChanged");return target;}
    private static void Hash(string hash){if(string.IsNullOrWhiteSpace(hash)||hash.Length>256)throw new ArgumentException("Invalid password hash.");}
    public Task<OperatorAccount> CreateAsync(string name,string displayName,OperatorRole[] roles,string passwordHash,bool mustChange,OperatorActor? actor,bool bootstrap,DateTimeOffset now,CancellationToken ct=default)
    {
        name=OperatorValidation.Name(name);OperatorValidation.Display(displayName);OperatorValidation.Roles(roles);Hash(passwordHash);roles=roles.ToArray();
        return Run(tx=>
        {
            OperatorAccount? creator=null;
            if(bootstrap)
            {using var count=Query(tx,"SELECT COUNT(*) FROM users");if(Convert.ToInt64(count.ExecuteScalar())!=0||actor is not null||roles.Length!=1||roles[0]!=OperatorRole.Administrator)throw new OperatorConflictException("BootstrapAlreadyCompleted");}
            else creator=RequireActor(tx,actor??throw new OperatorAccessException(),true).Account;
            using(var count=Query(tx,"SELECT COUNT(*) FROM users"))if(Convert.ToInt64(count.ExecuteScalar())>=_options.MaximumUsers)throw new IOException("Operator user capacity reached.");
            if(Find(tx,"name",name)is not null)throw new OperatorConflictException("OperatorNameExists");Clock(tx,now);
            var account=new OperatorAccount(Guid.NewGuid(),name,displayName,roles,true,mustChange,1,now,now);
            Execute(tx,"INSERT INTO users VALUES($id,$name,$display,$roles,1,$change,1,$now,$now,NULL,$hash,$stamp,0,NULL)",("$id",account.Id.ToString("D")),("$name",name),("$display",displayName),("$roles",JsonSerializer.Serialize(roles,OperatorValidation.Json)),("$change",mustChange),("$now",now.UtcTicks),("$hash",passwordHash),("$stamp",Guid.NewGuid().ToString("D")));
            Event(tx,now,creator,bootstrap?"AdministratorBootstrapped":"OperatorCreated",account,JsonSerializer.Serialize(new{roles,mustChange},OperatorValidation.Json));return account;
        },ct);
    }
    public Task<OperatorSession?> RecordLoginAsync(string normalizedName,Guid? expectedStamp,bool passwordMatched,string? remote,DateTimeOffset now,TimeSpan lifetime,CancellationToken ct=default)
    {
        if(normalizedName.Length>64||remote?.Length>64||lifetime<TimeSpan.FromMinutes(5)||lifetime>TimeSpan.FromHours(24))throw new ArgumentException("Invalid login input.");
        return Run<OperatorSession?>(tx=>
        {
            Clock(tx,now);var user=Find(tx,"name",normalizedName);bool valid=user is not null&&user.SecurityStamp==expectedStamp&&user.Account.Enabled&&(user.LockedUntilUtc is null||user.LockedUntilUtc<=now)&&passwordMatched;
            if(!valid)
            {
                if(user is not null&&user.SecurityStamp==expectedStamp&&user.Account.Enabled&&(user.LockedUntilUtc is null||user.LockedUntilUtc<=now))
                {
                    int attempts=(user.LockedUntilUtc is not null?0:user.FailedAttempts)+1;long? until=attempts>=5?now.AddMinutes(5).UtcTicks:null;
                    Execute(tx,"UPDATE users SET failures=$attempts,locked_until=$until WHERE id=$id",("$attempts",attempts),("$until",until),("$id",user.Account.Id.ToString("D")));
                }
                Event(tx,now,null,"LoginRejected",user?.Account,remote:remote,anonymous:normalizedName.Length==0?"unknown":normalizedName);return null;
            }
            Execute(tx,"DELETE FROM sessions WHERE expires<=$now",("$now",now.UtcTicks));
            using(var count=Query(tx,"SELECT COUNT(*) FROM sessions"))if(Convert.ToInt64(count.ExecuteScalar())>=_options.MaximumSessions)throw new IOException("Operator session capacity reached.");
            using(var count=Query(tx,"SELECT COUNT(*) FROM sessions WHERE user_id=$id",("$id",user!.Account.Id.ToString("D"))))if(Convert.ToInt64(count.ExecuteScalar())>=50)throw new OperatorConflictException("OperatorSessionLimit");
            var session=new OperatorSession(Guid.NewGuid(),user!.Account with{LastLoginUtc=now},user.SecurityStamp,now,now+lifetime);
            Execute(tx,"INSERT INTO sessions VALUES($id,$user,$stamp,$now,$expires)",("$id",session.Id.ToString("D")),("$user",user.Account.Id.ToString("D")),("$stamp",user.SecurityStamp.ToString("D")),("$now",now.UtcTicks),("$expires",session.ExpiresUtc.UtcTicks));
            Execute(tx,"UPDATE users SET failures=0,locked_until=NULL,last_login=$now WHERE id=$id",("$now",now.UtcTicks),("$id",user.Account.Id.ToString("D")));
            Event(tx,now,user.Account,"LoginAccepted",user.Account,remote:remote);return session;
        },ct);
    }
    public Task<OperatorSession?> ReadSessionAsync(Guid sessionId,Guid userId,Guid stamp,DateTimeOffset now,CancellationToken ct=default)=>Run<OperatorSession?>(tx=>
    {
        using(var head=Query(tx,"SELECT last_ticks FROM operator_metadata WHERE singleton=1"))if(now.Offset!=TimeSpan.Zero||now.UtcTicks<Convert.ToInt64(head.ExecuteScalar()))return null;
        var user=Find(tx,"id",userId.ToString("D"));if(user is null||!user.Account.Enabled||user.SecurityStamp!=stamp)return null;
        using var q=Query(tx,"SELECT created,expires,stamp FROM sessions WHERE id=$id AND user_id=$user",("$id",sessionId.ToString("D")),("$user",userId.ToString("D")));using var r=q.ExecuteReader();
        return r.Read()&&r.GetString(2)==stamp.ToString("D")&&r.GetInt64(0)<=now.UtcTicks&&r.GetInt64(1)>now.UtcTicks?new OperatorSession(sessionId,user.Account,stamp,Utc(r.GetInt64(0)),Utc(r.GetInt64(1))):null;
    },ct);
    public Task RevokeSessionAsync(Guid sessionId,Guid userId,DateTimeOffset now,CancellationToken ct=default)=>Run(tx=>
    {Clock(tx,now);using var q=Query(tx,"DELETE FROM sessions WHERE id=$id AND user_id=$user",("$id",sessionId.ToString("D")),("$user",userId.ToString("D")));if(q.ExecuteNonQuery()>0)Event(tx,now,Find(tx,"id",userId.ToString("D"))?.Account,"SignedOut",null);return 0;},ct);
    private void Rotate(SqliteTransaction tx,Guid id)
    {Execute(tx,"UPDATE users SET stamp=$stamp,failures=0,locked_until=NULL WHERE id=$id;DELETE FROM sessions WHERE user_id=$id",("$stamp",Guid.NewGuid().ToString("D")),("$id",id.ToString("D")));}
    public Task<OperatorAccount> UpdateAsync(Guid id,long expectedRevision,string displayName,OperatorRole[] roles,bool enabled,OperatorActor actor,DateTimeOffset now,CancellationToken ct=default)
    {
        OperatorValidation.Display(displayName);OperatorValidation.Roles(roles);roles=roles.ToArray();return Run(tx=>
        {
            var admin=RequireActor(tx,actor,true).Account;var current=RequireTarget(tx,id,expectedRevision).Account;Clock(tx,now);
            if(current.Enabled&&current.Roles.Contains(OperatorRole.Administrator)&&(!enabled||!roles.Contains(OperatorRole.Administrator)))
            {
                using var count=Query(tx,"SELECT roles FROM users WHERE enabled=1 AND id<>$id",("$id",id.ToString("D")));using var r=count.ExecuteReader();bool other=false;
                while(r.Read())other|=(JsonSerializer.Deserialize<OperatorRole[]>(r.GetString(0),OperatorValidation.Json)??[]).Contains(OperatorRole.Administrator);
                if(!other)throw new OperatorConflictException("LastAdministrator");
            }
            Execute(tx,"UPDATE users SET display=$display,roles=$roles,enabled=$enabled,revision=revision+1,updated=$now WHERE id=$id",("$display",displayName),("$roles",JsonSerializer.Serialize(roles,OperatorValidation.Json)),("$enabled",enabled),("$now",now.UtcTicks),("$id",id.ToString("D")));Rotate(tx,id);
            var updated=Find(tx,"id",id.ToString("D"))!.Account;Event(tx,now,admin,"OperatorUpdated",updated,JsonSerializer.Serialize(new{roles,enabled,displayName,updated.Revision},OperatorValidation.Json));return updated;
        },ct);
    }
    public Task ResetPasswordAsync(Guid id,long expectedRevision,string hash,OperatorActor actor,DateTimeOffset now,CancellationToken ct=default)
    {Hash(hash);return Run(tx=>{var admin=RequireActor(tx,actor,true).Account;var target=RequireTarget(tx,id,expectedRevision).Account;Clock(tx,now);
        Execute(tx,"UPDATE users SET password_hash=$hash,must_change=1,revision=revision+1,updated=$now WHERE id=$id",("$hash",hash),("$now",now.UtcTicks),("$id",id.ToString("D")));Rotate(tx,id);Event(tx,now,admin,"PasswordReset",target);return 0;},ct);}
    public Task<bool> ChangePasswordAsync(OperatorActor actor,string expectedHash,string newHash,DateTimeOffset now,CancellationToken ct=default)
    {Hash(newHash);return Run(tx=>{var target=RequireActor(tx,actor,false);if(target.PasswordHash!=expectedHash)return false;Clock(tx,now);
        Execute(tx,"UPDATE users SET password_hash=$hash,must_change=0,revision=revision+1,updated=$now WHERE id=$id",("$hash",newHash),("$now",now.UtcTicks),("$id",actor.UserId.ToString("D")));Rotate(tx,actor.UserId);Event(tx,now,target.Account,"PasswordChanged",target.Account);return true;},ct);}
    public Task RevokeAllAsync(Guid id,long expectedRevision,OperatorActor actor,DateTimeOffset now,CancellationToken ct=default)=>Run(tx=>
    {var admin=RequireActor(tx,actor,true).Account;var target=RequireTarget(tx,id,expectedRevision).Account;Clock(tx,now);Execute(tx,"UPDATE users SET revision=revision+1,updated=$now WHERE id=$id",("$now",now.UtcTicks),("$id",id.ToString("D")));Rotate(tx,id);Event(tx,now,admin,"SessionsRevoked",target);return 0;},ct);
    public Task RecoverAdministratorAsync(string name,string passwordHash,DateTimeOffset now,CancellationToken ct=default)
    {
        name=OperatorValidation.Name(name);Hash(passwordHash);return Run(tx=>{var target=Find(tx,"name",name)??throw new KeyNotFoundException();Clock(tx,now);
            Execute(tx,"UPDATE users SET password_hash=$hash,roles=$roles,enabled=1,must_change=1,revision=revision+1,updated=$now WHERE id=$id",("$hash",passwordHash),("$roles",JsonSerializer.Serialize(new[]{OperatorRole.Administrator},OperatorValidation.Json)),("$now",now.UtcTicks),("$id",target.Account.Id.ToString("D")));Rotate(tx,target.Account.Id);Event(tx,now,null,"AdministratorRecoveredLocally",target.Account);return 0;},ct);
    }
    public Task<OperatorPage> ReadUsersAsync(string? after=null,int limit=50,CancellationToken ct=default)
    {
        if(after?.Length>64||limit is <1 or >100)throw new ArgumentException("Invalid user query.");return Run(tx=>
        {using var q=Query(tx,$"SELECT {Columns} FROM users WHERE name>$after ORDER BY name LIMIT $limit",("$after",after??""),("$limit",limit+1));using var r=q.ExecuteReader();var users=new List<OperatorAccount>();while(r.Read())users.Add(Read(r).Account);bool more=users.Count>limit;if(more)users.RemoveAt(users.Count-1);return new OperatorPage(users.ToArray(),more?users[^1].UserName:null);},ct);
    }
    public Task<OperatorSecurityPage> ReadSecurityAsync(long? before=null,int limit=50,CancellationToken ct=default)
    {
        if(before is <1||limit is <1 or >100)throw new ArgumentException("Invalid security history query.");return Run(tx=>
        {using var q=Query(tx,"SELECT sequence,occurred,actor_id,actor,action,target_id,target,detail,remote FROM security_events WHERE ($before IS NULL OR sequence<$before) ORDER BY sequence DESC LIMIT $limit",("$before",before),("$limit",limit+1));using var r=q.ExecuteReader();var events=new List<OperatorSecurityEvent>();while(r.Read())events.Add(new(r.GetInt64(0),Utc(r.GetInt64(1)),r.IsDBNull(2)?null:Guid.Parse(r.GetString(2)),r.GetString(3),r.GetString(4),r.IsDBNull(5)?null:Guid.Parse(r.GetString(5)),r.IsDBNull(6)?null:r.GetString(6),r.IsDBNull(7)?null:r.GetString(7),r.IsDBNull(8)?null:r.GetString(8)));bool more=events.Count>limit;if(more)events.RemoveAt(events.Count-1);return new OperatorSecurityPage(events.ToArray(),more?events[^1].Sequence:null);},ct);
    }
    public async ValueTask DisposeAsync(){await _gate.WaitAsync();try{if(_disposed)return;_disposed=true;_db.Dispose();_writer.Dispose();}finally{_gate.Release();}}
}
