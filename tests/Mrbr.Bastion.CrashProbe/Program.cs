using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Ingestion;
using Mrbr.Bastion.Ingestion.Sqlite;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Auditing.Sqlite;
using Mrbr.Bastion.Notifications.Sqlite;

namespace Mrbr.Bastion.CrashProbe;

/// <summary>Child-process test helper; intentionally held in an uncommitted transaction until the parent kills it.</summary>
public static class Program
{
    public static async Task Main(string[] args)
    {
        if(args is ["--retain-crash",var retentionDatabase,var retentionPrivate,var retentionReceiver,var retentionStage])
        {
            using var nodeKey=ECDsa.Create();nodeKey.ImportFromPem(File.ReadAllText(retentionPrivate));
            using var receiverKey=ECDsa.Create();receiverKey.ImportFromPem(File.ReadAllText(retentionReceiver));
            using var node=new EcdsaSignatureProvider(nodeKey,"node-key");using var receiver=new EcdsaSignatureProvider(receiverKey,"server-key");
            var point=Enum.Parse<RetentionStage>(retentionStage);
            await using var retentionCache=await DurableTelemetryCache.OpenAsync(new(){NodeId="test-node",DatabasePath=retentionDatabase,
                Retention=new(){Enabled=true,KeepRecentBlocks=0,MinimumAgeSeconds=0},RetentionProbe=stage=>
                {if(stage==point){Console.WriteLine("READY");Console.Out.Flush();Task.Delay(Timeout.Infinite).GetAwaiter().GetResult();}}},node,node,receiver);
            await retentionCache.ApplyRetentionAsync();return;
        }
        if (args is ["--desktop-control"] or ["--desktop-control-policy"])
        {
            using var stop = new CancellationTokenSource();
            Action<string>? update = args[0] == "--desktop-control-policy" ? policy => Console.WriteLine("FILE POLICY " + policy) : null;
            await using var control = Mrbr.Bastion.Hosting.LocalProcessControl.FromEnvironment(stop.Cancel, update);
            Console.WriteLine("CONTROL READY");
            if (update is not null) Console.WriteLine("INITIAL POLICY " + Environment.GetEnvironmentVariable(Mrbr.Bastion.Hosting.LocalProcessControl.FileIoProcessesVariable));
            try { await Task.Delay(Timeout.Infinite, stop.Token); }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            Console.WriteLine("CONTROL STOPPED");
            return;
        }
        if (args is ["--notifications", var notificationDatabase, var clockTicks])
        {
            await using var queue = await SqliteNotificationQueue.OpenAsync(new() { DatabasePath = notificationDatabase });
            var now = new DateTimeOffset(long.Parse(clockTicks, System.Globalization.CultureInfo.InvariantCulture), TimeSpan.Zero);
            _ = await queue.LeaseAsync(["test-route"], now, TimeSpan.FromSeconds(60)) ?? throw new InvalidDataException("No queued test delivery.");
            using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = notificationDatabase, Pooling = false }.ToString()); db.Open();
            using (var setup = db.CreateCommand()) { setup.CommandText = "PRAGMA cache_size=1"; setup.ExecuteNonQuery(); }
            using var tx = db.BeginTransaction(); using var edit = db.CreateCommand(); edit.Transaction = tx;
            edit.CommandText = "UPDATE deliveries SET body=zeroblob(65536),last_code='uncommitted'; UPDATE attempts SET code='uncommitted'";
            edit.ExecuteNonQuery(); Console.WriteLine("READY"); await Task.Delay(Timeout.Infinite); return;
        }
        if (args is ["--audit", var auditDatabase, var responsePath, var nodePublicPath, var receiverPrivatePath])
        {
            var response = TelemetryJson.Decode<SignedAuditResponse>(File.ReadAllBytes(responsePath), AuditProtocol.MaximumEnvelopeBytes);
            using var nodeKey = ECDsa.Create(); nodeKey.ImportFromPem(File.ReadAllText(nodePublicPath));
            using var receiverKey = ECDsa.Create(); receiverKey.ImportFromPem(File.ReadAllText(receiverPrivatePath));
            using var node = new EcdsaSignatureProvider(nodeKey, response.Content.KeyId);
            using var receiver = new EcdsaSignatureProvider(receiverKey, "server-key");
            var trust = new StaticNodeTrustStore([new(response.Content.NodeId, response.Content.LedgerId, node)]);
            await using var store = await SqliteHeartbeatAuditStore.OpenAsync(new() { DatabasePath = auditDatabase }, trust, receiver,
                new FixedClock(response.Content.SampledUtc));
            await store.CompleteAsync(response, (previous, challenge, now) =>
            {
                var r = response.Content;
                var content = new AuditResultContent(1, r.NodeId, r.LedgerId, r.CollectorRunId, r.ChallengeId, r.ChallengeHash,
                    AuditProtocol.Hash(AuditProtocol.Encode(r)), (previous?.Result.Content.AuditSequenceNumber ?? 0) + 1,
                    previous is null ? AuditProtocol.GenesisHash : AuditProtocol.Hash(AuditProtocol.Encode(previous.Result.Content)), now, [], 0, 0,
                    new("mrbr.bastion.audit-verification.v1", 30000, 1000, 134217728), receiver.Algorithm, receiver.KeyId);
                return new(content, receiver.Sign(AuditProtocol.Encode(content)));
            });
            using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = auditDatabase, Pooling = false }.ToString()); db.Open();
            using (var settings = db.CreateCommand()) { settings.CommandText = "PRAGMA cache_size=1"; settings.ExecuteNonQuery(); }
            using var interrupted = db.BeginTransaction(); using var corrupt = db.CreateCommand(); corrupt.Transaction = interrupted;
            corrupt.CommandText = "UPDATE audit_entries SET result_json=zeroblob(16384); UPDATE node_heads SET result_hash='uncommitted'";
            corrupt.ExecuteNonQuery(); Console.WriteLine("READY"); await Task.Delay(Timeout.Infinite); return;
        }
        if (args is ["--ingestion", var centralDatabase, var blockPath, var nodePublicKeyPath, var receiptPrivateKeyPath])
        {
            var block = TelemetryJson.Decode<SignedTelemetryBlock>(File.ReadAllBytes(blockPath), TelemetryJson.MaximumBlockBytes);
            using var nodeKey = ECDsa.Create(); nodeKey.ImportFromPem(File.ReadAllText(nodePublicKeyPath));
            using var receiverKey = ECDsa.Create(); receiverKey.ImportFromPem(File.ReadAllText(receiptPrivateKeyPath));
            using var node = new EcdsaSignatureProvider(nodeKey, block.Content.KeyId);
            using var receiver = new EcdsaSignatureProvider(receiverKey, "server-key");
            var trust = new StaticNodeTrustStore([new(block.Content.NodeId, block.Content.LedgerId, node)]);
            await using var store = await SqliteIngestionStore.OpenAsync(new() { DatabasePath = centralDatabase }, trust, receiver);
            await new TelemetryIngestionService(trust, store, receiver, receiver).IngestAsync(block);
            using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = centralDatabase, Pooling = false }.ToString());
            db.Open();
            using (var settings = db.CreateCommand()) { settings.CommandText = "PRAGMA cache_size=1"; settings.ExecuteNonQuery(); }
            using var interrupted = db.BeginTransaction();
            using var corrupt = db.CreateCommand(); corrupt.Transaction = interrupted;
            corrupt.CommandText = "UPDATE ingested_blocks SET receipt=zeroblob(16384); UPDATE ledgers SET tail_hash='uncommitted'";
            corrupt.ExecuteNonQuery();
            Console.WriteLine("READY");
            await Task.Delay(Timeout.Infinite);
            return;
        }
        if (args is ["--io", var probePath])
        {
            File.WriteAllText(probePath, "Mrbr.Bastion ETW probe");
            _ = File.ReadAllText(probePath);
            return;
        }
        if (args is not [var database, var privateKey]) throw new ArgumentException("Expected database and test key paths.");
        using var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(privateKey));
        using var signer = new EcdsaSignatureProvider(key, "node-key");
        await using var cache = await DurableTelemetryCache.OpenAsync(
            new DurableCacheOptions { DatabasePath = database, NodeId = "test-node" }, signer, signer, signer);
        await cache.AppendAsync([new TelemetryEvent
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Kind = TelemetryEventKind.ProcessStarted,
            ProcessId = Environment.ProcessId,
            Source = "crash-probe"
        }]);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database, Pooling = false }.ToString());
        connection.Open();
        using (var settings = connection.CreateCommand())
        {
            settings.CommandText = "PRAGMA cache_size=1; PRAGMA synchronous=FULL";
            settings.ExecuteNonQuery();
        }
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            WITH RECURSIVE numbers(x) AS (SELECT 2 UNION ALL SELECT x+1 FROM numbers WHERE x<1000)
            INSERT INTO blocks(sequence,block_id,body,payload_bytes) SELECT x,CAST(x AS TEXT),zeroblob(4096),4096 FROM numbers;
            UPDATE ledger SET last_sequence=1000,tail_hash='uncommitted';
            """;
        command.ExecuteNonQuery();
        Console.WriteLine("READY");
        await Task.Delay(Timeout.Infinite); // Parent terminates this process without Dispose or transaction rollback.
    }
}

internal sealed class FixedClock(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}
