using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Archiving;
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Inventory.Contracts;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class CacheRetentionTests
{
    private static DurableCacheOptions Options(TestLedger f, int keep = 0) => f.Options with
    { Retention = new() { Enabled=true,KeepRecentBlocks=keep,MinimumAgeSeconds=0,MaximumBlocksPerSegment=32 } };
    private static Task<DurableTelemetryCache> Open(TestLedger f, DurableCacheOptions options, LedgerCheckpoint? anchor = null) =>
        DurableTelemetryCache.OpenAsync(options,f.Node,f.Node,f.Server,anchor);

    [Fact]
    public async Task SettledPrefixRoundTripsAcrossPendingGapsOldAnchorsAndDisabledMaintenance()
    {
        using var f=new TestLedger();var options=Options(f,1); options.Retention.ArchiveDirectory="custom-history"; SignedTelemetryBlock first,third;CacheStatus before;
        await using(var cache=await Open(f,options))
        {
            first=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(first));
            var second=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(second));
            third=await cache.AppendAsync([TestLedger.Event()]);
            var fourth=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(fourth));
            await cache.AppendAsync([TestLedger.Event()]);before=await cache.GetStatusAsync();
            var result=await cache.ApplyRetentionAsync();Assert.Equal(2,result.ArchivedBlocks);
            Assert.Equal(before,await cache.GetStatusAsync());Assert.Equal(3,result.Storage.ResidentBlocks);
            Assert.Equal([3L,5L],(await cache.ReadPendingAsync()).Select(b=>b.Content.SequenceNumber));
            await cache.ReconcileAsync(f.Receipt(first)); // Archived duplicate receipt stays idempotent.
            await cache.ReconcileAsync(f.Receipt(third));Assert.Equal(2,(await cache.ApplyRetentionAsync()).ArchivedBlocks);
            var oldAnchor=new LedgerCheckpoint(first.Content.NodeId,first.Content.LedgerId,1,first.BlockHash);
            await cache.VerifyIntegrityAsync(oldAnchor);
            await Assert.ThrowsAsync<InvalidDataException>(()=>cache.VerifyIntegrityAsync(oldAnchor with{BlockHash=new string('A',64)}));
        }
        await using var reopened=await Open(f,options with{Retention=new(){Enabled=false}});
        Assert.Contains("custom-history",(await reopened.GetStorageStatusAsync()).ArchiveDirectory);
        Assert.Equal(5,(await reopened.GetStatusAsync()).Checkpoint.SequenceNumber);
        Assert.Equal(4,(await reopened.GetStorageStatusAsync()).ArchivedBlocks);
        Assert.Equal(5,Assert.Single(await reopened.ReadPendingAsync()).Content.SequenceNumber);
        await reopened.AppendAsync([TestLedger.Event()]);await reopened.VerifyIntegrityAsync();
    }

    private sealed class Clock : TimeProvider { public DateTimeOffset Now { get; set; }=DateTimeOffset.UtcNow;public override DateTimeOffset GetUtcNow()=>Now; }
    [Fact]
    public async Task AgeAndRecentWindowBothProtectSettledBlocks()
    {
        using var f=new TestLedger();var clock=new Clock();var options=Options(f,2) with{TimeProvider=clock};options.Retention.MinimumAgeSeconds=3600;
        await using var cache=await Open(f,options);
        for(int i=0;i<5;i++){var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(b));}
        Assert.Equal(0,(await cache.ApplyRetentionAsync()).ArchivedBlocks);
        clock.Now=DateTimeOffset.UtcNow.AddHours(2);Assert.Equal(3,(await cache.ApplyRetentionAsync()).ArchivedBlocks);
        Assert.Equal(2,(await cache.GetStorageStatusAsync()).ResidentBlocks);
    }

    [Fact]
    public async Task CapacityPressureArchivesSettledHistoryButNeverDiscardsPendingBlocks()
    {
        using var f=new TestLedger();var options=Options(f) with{MaximumPayloadBytes=1024,MaximumStoredPayloadBytes=2048};
        await using var cache=await Open(f,options);
        for(int i=0;i<12;i++){var b=await cache.AppendAsync([TestLedger.Event(path:new string('x',100))]);await cache.ReconcileAsync(f.Receipt(b));}
        Assert.True((await cache.GetStorageStatusAsync()).ArchivedBlocks>0);
        Assert.True((await cache.GetStatusAsync()).StoredPayloadBytes>2048);
        while(true)
        {
            var pending=await cache.ReadPendingAsync();
            try{await cache.AppendAsync([TestLedger.Event(path:new string('y',100))]);}
            catch(IOException){Assert.Equal(pending.Select(b=>b.BlockHash),(await cache.ReadPendingAsync()).Select(b=>b.BlockHash));break;}
        }
        Assert.NotEmpty(await cache.ReadPendingAsync());Assert.True((await cache.GetStorageStatusAsync()).ResidentPayloadBytes<=2048);
        await cache.VerifyIntegrityAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingOrTamperedArchiveFailsClosedOnRestart(bool corrupt)
    {
        using var f=new TestLedger();var options=Options(f);string path;
        await using(var cache=await Open(f,options))
        {
            var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(b));await cache.ApplyRetentionAsync();
            path=Path.Combine((await cache.GetStorageStatusAsync()).ArchiveDirectory,Assert.Single(await cache.GetArchivesAsync()).FileName);
            if(OperatingSystem.IsWindows())Assert.Throws<IOException>(()=>File.WriteAllBytes(path,[]));
        }
        // Change only JSON property casing: block/receipt signatures still verify, but the file digest must fail.
        if(corrupt){var bytes=File.ReadAllBytes(path);Assert.Equal((byte)'C',bytes[14]);bytes[14]=(byte)'c';File.WriteAllBytes(path,bytes);}else File.Delete(path);
        var error=await Assert.ThrowsAsync<InvalidDataException>(()=>Open(f,options));
        if(corrupt)Assert.Contains("digest",error.Message,StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task QuotaFailureKeepsAllResidentEvidenceAndReportsError()
    {
        using var f=new TestLedger();var options=Options(f);options.Retention.MaximumArchiveBytes=1024;
        await using var cache=await Open(f,options);var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(b));
        var before=await cache.GetStatusAsync();await Assert.ThrowsAsync<IOException>(()=>cache.ApplyRetentionAsync());
        Assert.Equal(before,await cache.GetStatusAsync());Assert.Empty(await cache.GetArchivesAsync());
        Assert.NotNull((await cache.GetStorageStatusAsync()).LastRetentionError);
    }

    [Fact]
    public async Task AllArchivedTailCanAppendAndCompactionPreservesProofs()
    {
        using var f=new TestLedger();var options=Options(f);await using var cache=await Open(f,options);
        for(int i=0;i<40;i++){var b=await cache.AppendAsync([TestLedger.Event(path:new string('x',16000))]);await cache.ReconcileAsync(f.Receipt(b));}
        f.Execute("PRAGMA wal_checkpoint(TRUNCATE)");
        long before=new FileInfo(options.DatabasePath).Length;await cache.ApplyRetentionAsync();
        Assert.Equal(0,(await cache.GetStorageStatusAsync()).ResidentBlocks);var tip=(await cache.GetStatusAsync()).Checkpoint;
        await cache.CompactAsync();Assert.Equal(tip,(await cache.GetStatusAsync()).Checkpoint);
        Assert.True(new FileInfo(options.DatabasePath).Length<before);
        var next=await cache.AppendAsync([TestLedger.Event()]);Assert.Equal(tip.SequenceNumber+1,next.Content.SequenceNumber);Assert.Equal(tip.BlockHash,next.Content.PreviousBlockHash);
        await cache.VerifyIntegrityAsync();
    }

    [Fact]
    public async Task InventoryArchivesKeepCodecValidationAndExactReceipts()
    {
        using var f=new TestLedger();var options=Options(f) with{AdditionalPayloadCodecs=[new InventoryPayloadCodec()]};string path;
        await using(var cache=await Open(f,options))
        {
            var row=SoftwareFixture.Record();var b=await cache.AppendPayloadAsync(LedgerProtocol.InventoryPayloadFormat,InventoryJson.Encode([row]),1);await cache.ReconcileAsync(f.Receipt(b));
            await cache.ApplyRetentionAsync();path=Path.Combine((await cache.GetStorageStatusAsync()).ArchiveDirectory,Assert.Single(await cache.GetArchivesAsync()).FileName);
            var segment=ArchiveFile.Verify(path,f.Node,f.Server,[new InventoryPayloadCodec()]);Assert.Equal(1,segment.Manifest.Content.LastSequence);
            Assert.Throws<InvalidDataException>(()=>ArchiveFile.Verify(path,f.Node,f.Server,[]));
        }
        await using var reopened=await Open(f,options);await reopened.VerifyIntegrityAsync();
    }

    [Fact]
    public async Task PruneTransactionRollbackAndCatalogTamperingDoNotHideHistory()
    {
        using var f=new TestLedger();bool fail=true;var options=Options(f) with{RetentionProbe=stage=>{if(fail&&stage==RetentionStage.BeforePruneCommit)throw new IOException("injected before commit");}};
        await using var cache=await Open(f,options);var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(b));var before=await cache.GetStatusAsync();
        await Assert.ThrowsAsync<IOException>(()=>cache.ApplyRetentionAsync());Assert.Equal(before,await cache.GetStatusAsync());Assert.Empty(await cache.GetArchivesAsync());
        fail=false;await cache.ApplyRetentionAsync();await cache.VerifyIntegrityAsync();
        f.Execute("DELETE FROM cache_archives");await Assert.ThrowsAsync<InvalidDataException>(()=>cache.CaptureAuditSnapshotAsync());
    }

    [Fact]
    public async Task ArchiveStorageFailureDoesNotPruneSettledRows()
    {
        using var f=new TestLedger();Directory.CreateDirectory(f.DirectoryPath);string unavailable=Path.Combine(f.DirectoryPath,"not-a-directory");File.WriteAllText(unavailable,"fixture");
        var options=Options(f);options.Retention.ArchiveDirectory=unavailable;
        await using var cache=await Open(f,options);var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(b));var before=await cache.GetStatusAsync();
        await Assert.ThrowsAnyAsync<IOException>(()=>cache.ApplyRetentionAsync());Assert.Equal(before,await cache.GetStatusAsync());Assert.Empty(await cache.GetArchivesAsync());
    }

    [Fact]
    public async Task CancellationAfterFileFlushKeepsResidentHistoryAndCanResume()
    {
        using var f=new TestLedger();using var stop=new CancellationTokenSource();bool cancel=true;
        var options=Options(f) with{RetentionProbe=stage=>{if(cancel&&stage==RetentionStage.ArchiveFlushed)stop.Cancel();}};
        await using var cache=await Open(f,options);var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(b));var before=await cache.GetStatusAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>cache.ApplyRetentionAsync(stop.Token));
        Assert.Equal(before,await cache.GetStatusAsync());Assert.Empty(await cache.GetArchivesAsync());Assert.Null((await cache.GetStorageStatusAsync()).LastRetentionError);
        cancel=false;Assert.Equal(1,(await cache.ApplyRetentionAsync()).ArchivedBlocks);await cache.VerifyIntegrityAsync();
    }

    [Fact]
    public async Task PreparedArchiveAllowsNewAppendsAndConsistentAuditsBeforePruneCommit()
    {
        using var f=new TestLedger();var ready=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var resume=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var options=Options(f) with{RetentionProbe=stage=>{if(stage==RetentionStage.ArchiveFlushed){ready.TrySetResult();resume.Task.GetAwaiter().GetResult();}}};
        await using var cache=await Open(f,options);
        for(int i=0;i<2;i++){var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(b));}
        var retaining=Task.Run(()=>cache.ApplyRetentionAsync());
        try
        {
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(5));await cache.AppendAsync([TestLedger.Event()]).WaitAsync(TimeSpan.FromSeconds(5));
            var audit=await cache.CaptureAuditSnapshotAsync().WaitAsync(TimeSpan.FromSeconds(5));Assert.Equal(3,audit.Checkpoint.SequenceNumber);Assert.Equal(1,audit.PendingBlocks);
        }
        finally{resume.TrySetResult();}
        Assert.Equal(2,(await retaining.WaitAsync(TimeSpan.FromSeconds(5))).ArchivedBlocks);
        Assert.Equal(3,Assert.Single(await cache.ReadPendingAsync()).Content.SequenceNumber);await cache.VerifyIntegrityAsync();
    }

    [Fact]
    public async Task ArchiveRejectsAValidReceiptForAnotherSignedBlock()
    {
        using var f=new TestLedger();await using var cache=await f.OpenAsync();var first=await cache.AppendAsync([TestLedger.Event()]);var second=await cache.AppendAsync([TestLedger.Event()]);
        var entry=new ArchiveEntry(JsonSerializer.SerializeToUtf8Bytes(first),JsonSerializer.SerializeToUtf8Bytes(f.Receipt(second)));
        Assert.Throws<InvalidDataException>(()=>ArchiveProtocol.VerifyEntry(entry,f.Node,f.Server,[]));
    }

    [Fact]
    public async Task UnexpectedDeleteTriggerCannotTurnRetentionIntoPendingEvidenceDeletion()
    {
        using var f=new TestLedger();await using var cache=await Open(f,Options(f));
        var settled=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(settled));await cache.AppendAsync([TestLedger.Event()]);
        var before=await cache.GetStatusAsync();var pending=Assert.Single(await cache.ReadPendingAsync());
        f.Execute("CREATE TRIGGER unsafe_prune AFTER DELETE ON blocks BEGIN DELETE FROM blocks WHERE receipt IS NULL; END");
        await Assert.ThrowsAsync<InvalidDataException>(()=>cache.ApplyRetentionAsync());
        Assert.Equal(before,await cache.GetStatusAsync());Assert.Equal(pending.BlockHash,Assert.Single(await cache.ReadPendingAsync()).BlockHash);
        f.Execute("DROP TRIGGER unsafe_prune");await cache.VerifyIntegrityAsync();
    }

    private sealed class CountingVerifier(ISignatureVerifier inner):ISignatureVerifier
    {
        public int Blocks;
        public bool Verify(string algorithm,string keyId,ReadOnlySpan<byte> data,ReadOnlySpan<byte> signature)
        {
            using var s=new MemoryStream(data.ToArray());using var r=new BinaryReader(s);
            if(r.ReadString()=="Mrbr.Bastion.Block.v1")Interlocked.Increment(ref Blocks);
            return inner.Verify(algorithm,keyId,data,signature);
        }
    }

    [Theory]
    [InlineData("ArchiveFlushed",false)]
    [InlineData("BeforePruneCommit",false)]
    [InlineData("AfterPruneCommit",true)]
    public async Task ProcessDeathLeavesEitherResidentEvidenceOrACompleteVerifiedArchive(string stage,bool pruned)
    {
        using var f=new TestLedger();var options=Options(f);LedgerCheckpoint head;
        await using(var cache=await Open(f,options))
        {
            for(int i=0;i<4;i++){var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(b));}
            head=(await cache.GetStatusAsync()).Checkpoint;
        }
        string node=Path.Combine(f.DirectoryPath,"node.pem"),receiver=Path.Combine(f.DirectoryPath,"receiver.pem");
        File.WriteAllText(node,f.NodeKey.ExportPkcs8PrivateKeyPem());File.WriteAllText(receiver,f.ServerKey.ExportSubjectPublicKeyInfoPem());
        using(var child=RecoveryAndEtwTests.StartProbe("--retain-crash",options.DatabasePath,node,receiver,stage))
        {
            try{Assert.Equal("READY",await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15)));}
            finally{if(!child.HasExited)child.Kill(entireProcessTree:true);await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));}
        }
        await using var reopened=await TestLedger.AfterProcessExitAsync(()=>Open(f,options,head));var storage=await reopened.GetStorageStatusAsync();
        Assert.Equal(pruned?0:4,storage.ResidentBlocks);Assert.Equal(pruned?4:0,storage.ArchivedBlocks);
        Assert.Equal(head,(await reopened.GetStatusAsync()).Checkpoint);Assert.Empty(await reopened.ReadPendingAsync());
        if(!pruned){Assert.Empty(await reopened.GetArchivesAsync());Assert.Single(Directory.GetFiles(storage.ArchiveDirectory,"*.bastion-archive"));await reopened.ApplyRetentionAsync();}
        await reopened.VerifyIntegrityAsync(head);var next=await reopened.AppendAsync([TestLedger.Event()]);Assert.Equal(5,next.Content.SequenceNumber);Assert.Equal(head.BlockHash,next.Content.PreviousBlockHash);
    }

    [Fact]
    public async Task ArchivedCacheCanContinueDeliveryAndSignedHeartbeatHistoryWithoutChangingEnrollment()
    {
        await using var f=await AuditFixture.CreateAsync();
        await f.Ledger.Cache.ReconcileAsync(await f.Ledger.Service.IngestAsync(f.Ledger.First));
        await f.Ledger.Cache.DisposeAsync();
        var options=Options(f.Ledger.Local);
        await using var cache=await Open(f.Ledger.Local,options);
        var before=await f.Agent(cache:cache).AuditOnceAsync();Assert.Empty(before.Content.Findings);
        await cache.ApplyRetentionAsync();
        for(int i=0;i<8;i++)
        {
            var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(await f.Ledger.Service.IngestAsync(b));
            await cache.ApplyRetentionAsync();
        }
        f.Metrics=new(MonitorState.Running,9,0,0,0,9,9,0,null);f.Clock.Advance(TimeSpan.FromSeconds(5));
        var after=await f.Agent(cache:cache).AuditOnceAsync();Assert.Empty(after.Content.Findings);
        Assert.Equal(before.Content.AuditSequenceNumber+1,after.Content.AuditSequenceNumber);
        Assert.Equal(Mrbr.Bastion.Auditing.Contracts.AuditProtocol.Hash(Mrbr.Bastion.Auditing.Contracts.AuditProtocol.Encode(before.Content)),after.Content.PreviousResultHash);
        Assert.True(Mrbr.Bastion.Auditing.Contracts.AuditProtocol.Verify(after,f.Ledger.Local.Server));
        Assert.Equal(f.Ledger.First.Content.LedgerId,(await cache.GetStatusAsync()).Checkpoint.LedgerId);
        Assert.Equal(9,(await cache.GetStorageStatusAsync()).ArchivedBlocks);Assert.Empty(await cache.ReadPendingAsync());
    }

    [Fact]
    public async Task MaintenanceAndPublicKeyArchiveVerificationToolsRunAgainstAnIsolatedDeployment()
    {
        using var f=new TestLedger();Directory.CreateDirectory(f.DirectoryPath);
        string privatePath=Path.Combine(f.DirectoryPath,"node-private.pem"),publicPath=Path.Combine(f.DirectoryPath,"node-public.pem"),receiverPath=Path.Combine(f.DirectoryPath,"receiver-public.pem");
        File.WriteAllText(privatePath,f.NodeKey.ExportPkcs8PrivateKeyPem());File.WriteAllText(publicPath,f.NodeKey.ExportSubjectPublicKeyInfoPem());File.WriteAllText(receiverPath,f.ServerKey.ExportSubjectPublicKeyInfoPem());
        using var node=new Mrbr.Bastion.Cryptography.EcdsaSignatureProvider(f.NodeKey,Mrbr.Bastion.Cryptography.EcdsaSignatureProvider.Fingerprint(f.NodeKey));
        using var receiver=new Mrbr.Bastion.Cryptography.EcdsaSignatureProvider(f.ServerKey,Mrbr.Bastion.Cryptography.EcdsaSignatureProvider.Fingerprint(f.ServerKey));
        var options=Options(f);LedgerCheckpoint head;
        await using(var cache=await DurableTelemetryCache.OpenAsync(options,node,node,receiver))
        {
            for(int i=0;i<3;i++)
            {
                var b=await cache.AppendAsync([TestLedger.Event()]);var c=new SettlementReceiptContent(1,b.Content.NodeId,b.Content.LedgerId,b.Content.BlockId,b.Content.SequenceNumber,b.BlockHash,DateTimeOffset.UtcNow,receiver.Algorithm,receiver.KeyId);
                await cache.ReconcileAsync(new(c,receiver.Sign(LedgerProtocol.EncodeReceipt(c))));
            }
            head=(await cache.GetStatusAsync()).Checkpoint;
        }
        string config=Path.Combine(f.DirectoryPath,"maintenance.json");
        File.WriteAllText(config,JsonSerializer.Serialize(new Mrbr.Bastion.Cache.Tool.MaintenanceSettings{NodeId=options.NodeId,DatabasePath="cache.db",NodePrivateKeyPath=privatePath,ReceiverPublicKeyPath=receiverPath,Retention=options.Retention},ArchiveProtocol.Json));
        Assert.Equal(0,await Mrbr.Bastion.Cache.Tool.Program.Main(["retain",config]));
        Assert.Equal(0,await Mrbr.Bastion.Cache.Tool.Program.Main(["verify",config]));
        Assert.Equal(0,await Mrbr.Bastion.Cache.Tool.Program.Main(["compact",config]));
        await using var reopened=await DurableTelemetryCache.OpenAsync(options,node,node,receiver,head);
        string archive=Path.Combine((await reopened.GetStorageStatusAsync()).ArchiveDirectory,Assert.Single(await reopened.GetArchivesAsync()).FileName);
        Assert.Equal(0,await Mrbr.Bastion.Cache.Tool.Program.Main(["verify-archive",archive,publicPath,receiverPath]));
    }
    [Fact]
    public async Task WindowsHeartbeatReusesPinnedVerifiedArchivesWhileExplicitScrubReadsThem()
    {
        using var f=new TestLedger();var options=Options(f,1);var verifier=new CountingVerifier(f.Node);
        await using var cache=await DurableTelemetryCache.OpenAsync(options,f.Node,verifier,f.Server);
        for(int i=0;i<20;i++){var b=await cache.AppendAsync([TestLedger.Event()]);await cache.ReconcileAsync(f.Receipt(b));}
        await cache.ApplyRetentionAsync();verifier.Blocks=0;await cache.CaptureAuditSnapshotAsync();
        if(OperatingSystem.IsWindows())Assert.Equal(1,verifier.Blocks);else Assert.True(verifier.Blocks>=20);
        verifier.Blocks=0;await cache.VerifyIntegrityAsync();Assert.True(verifier.Blocks>=20);
    }
}
