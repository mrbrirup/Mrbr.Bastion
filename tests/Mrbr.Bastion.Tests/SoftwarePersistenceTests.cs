using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Alerting.Sqlite;
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Ingestion;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Software.Hosting;
using Mrbr.Bastion.Transport.Http;
using Mrbr.Bastion.Transport.Grpc;
using Mrbr.Bastion.Vulnerabilities;
using Mrbr.Bastion.Vulnerabilities.Sqlite;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class SoftwarePersistenceTests
{
    [Theory][InlineData(false)][InlineData(true)]
    public async Task SignedInventoryUsesExistingTransportsAndRequiresExplicitReceiverOptIn(bool grpc)
    {
        await using var f=await SoftwareFixture.CreateAsync();var row=SoftwareFixture.Record();
        var block=await f.Cache.AppendPayloadAsync(LedgerProtocol.InventoryPayloadFormat,InventoryJson.Encode([row]),1);
        var legacy=new TelemetryIngestionService(f.Trust,f.Ledger,f.Local.Server,f.Local.Server);
        Assert.Equal(IngestionFailure.InvalidBlock,(await Assert.ThrowsAsync<TelemetryRejectedException>(()=>legacy.IngestAsync(block))).Failure);
        await using(var host=await NetworkIngestionHost.StartAsync(f.Service))
        {
            if(grpc){await using var transport=new GrpcTelemetryTransport(host.GrpcAddress,f.Local.Server,host.ClientOptions);await f.Cache.ReconcileAsync(await transport.SubmitAsync(block));}
            else{using var transport=new HttpTelemetryTransport(host.Address,f.Local.Server,host.ClientOptions);await f.Cache.ReconcileAsync(await transport.SubmitAsync(block));}
        }
        Assert.Empty(await f.Cache.ReadPendingAsync());await f.Ledger.VerifyIntegrityAsync();
        await f.Cache.DisposeAsync();await using var reopened=await DurableTelemetryCache.OpenAsync(f.Local.Options with{AdditionalPayloadCodecs=[new InventoryPayloadCodec()]},f.Local.Node,f.Local.Node,f.Local.Server);
        Assert.Equal(1,(await reopened.GetStatusAsync()).Checkpoint.SequenceNumber);
        await reopened.DisposeAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>DurableTelemetryCache.OpenAsync(f.Local.Options,f.Local.Node,f.Local.Node,f.Local.Server));
    }
    [Fact]
    public async Task CountsAndAuthenticatedInventorySchemaAreVerifiedBeforeReceiptIssuance()
    {
        await using var f=await SoftwareFixture.CreateAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>f.Cache.AppendPayloadAsync(LedgerProtocol.InventoryPayloadFormat,InventoryJson.Encode([SoftwareFixture.Record()]),2));
        var good=await f.Cache.AppendPayloadAsync(LedgerProtocol.InventoryPayloadFormat,InventoryJson.Encode([SoftwareFixture.Record()]),1);
        var content=good.Content with{EventCount=2};var bytes=LedgerProtocol.EncodeBlock(content);var malformed=new SignedTelemetryBlock(content,Convert.ToHexString(SHA256.HashData(bytes)),f.Local.Node.Sign(bytes));
        Assert.Equal(IngestionFailure.InvalidBlock,(await Assert.ThrowsAsync<TelemetryRejectedException>(()=>f.Service.IngestAsync(malformed))).Failure);
        Assert.Null(await f.Ledger.GetCheckpointAsync(f.Node,f.LedgerId));
        Assert.Throws<InvalidDataException>(()=>InventoryJson.Encode([SoftwareFixture.Record() with{Artifact=new("x",Sha256:"bad")} ]));
    }
    [Fact]
    public async Task ProjectionIsAtomicResumableAndRefusesReusedRecordIdentity()
    {
        await using var f=await SoftwareFixture.CreateAsync();var row=SoftwareFixture.Record();var first=await f.AppendAsync(row);await f.Inventory.ApplyAsync(first,DateTimeOffset.UtcNow);await f.Inventory.ApplyAsync(first,DateTimeOffset.UtcNow);
        Assert.Single((await f.Inventory.ReadAsync(f.Node,f.LedgerId)).Items);
        var duplicate=await f.AppendAsync(row);await f.Inventory.ApplyAsync(duplicate,DateTimeOffset.UtcNow);Assert.Single((await f.Inventory.ReadAsync(f.Node,f.LedgerId)).Items);
        var changed=await f.AppendAsync(row with{Artifact=row.Artifact! with{ProductVersion="2.0"}});
        await Assert.ThrowsAsync<InvalidDataException>(()=>f.Inventory.ApplyAsync(changed,DateTimeOffset.UtcNow));
        Assert.Equal(2,(await f.Inventory.CheckpointAsync(f.Node,f.LedgerId)).SequenceNumber);
        await f.Inventory.DisposeAsync();await using var reopened=SqliteInventoryStore.Open(f.PathFor("inventory.db"));
        Assert.Equal(2,(await reopened.CheckpointAsync(f.Node,f.LedgerId)).SequenceNumber);
    }
    [Fact]
    public async Task PartialScansAndContradictoryCoverageCannotMarkPriorItemsMissing()
    {
        await using var f=await SoftwareFixture.CreateAsync();var old=await f.AppendAsync(SoftwareFixture.Record());await f.Inventory.ApplyAsync(old,DateTimeOffset.UtcNow);
        Guid scan=Guid.NewGuid();var partial=await f.AppendAsync(SoftwareFixture.Record(InventoryRecordKind.Coverage,scan),SoftwareFixture.Record(InventoryRecordKind.ScanCompleted,scan,complete:true));await f.Inventory.ApplyAsync(partial,DateTimeOffset.UtcNow);
        Assert.False(Assert.Single((await f.Inventory.ReadAsync(f.Node,f.LedgerId)).Items).Missing);
        Assert.Contains(await f.Inventory.ReadScansAsync(f.Node,f.LedgerId),s=>s.ScanId==scan&&s.Finished&&!s.Complete);
        Assert.Single(await f.Inventory.ReadCoverageAsync(f.Node,f.LedgerId,scan));
        var complete=await f.AppendAsync(SoftwareFixture.Record(InventoryRecordKind.ScanCompleted,complete:true));await f.Inventory.ApplyAsync(complete,DateTimeOffset.UtcNow);
        Assert.True(Assert.Single((await f.Inventory.ReadAsync(f.Node,f.LedgerId)).Items).Missing);
    }
    [Fact]
    public async Task ProjectionCapacityAndCursorConflictsLeaveTheCursorUnchanged()
    {
        await using var f=await SoftwareFixture.CreateAsync(maximum:1);var first=await f.AppendAsync(SoftwareFixture.Record());await f.Inventory.ApplyAsync(first,DateTimeOffset.UtcNow);
        var second=await f.AppendAsync(SoftwareFixture.Record(artifact:new("another.exe")));
        await Assert.ThrowsAsync<IOException>(()=>f.Inventory.ApplyAsync(second,DateTimeOffset.UtcNow));
        Assert.Equal(1,(await f.Inventory.CheckpointAsync(f.Node,f.LedgerId)).SequenceNumber);
        await Assert.ThrowsAsync<InvalidDataException>(()=>f.Inventory.ApplyAsync(first with{BlockHash=LedgerProtocol.GenesisHash},DateTimeOffset.UtcNow));
    }
    [Fact]
    public async Task ProcessStopsRetainMetadataAndPidsFromDifferentLifetimesDoNotMerge()
    {
        await using var f=await SoftwareFixture.CreateAsync();var instance=Guid.NewGuid();var a=new SoftwareArtifact("proc.exe",Publisher:"Vendor",Product:"Widget",ProductVersion:"1.2",ProcessId:42,ProcessInstanceId:instance,ReportedRunning:true,MetadataUtc:DateTimeOffset.UtcNow.AddMinutes(-1));
        var start=SoftwareFixture.Record(artifact:a,source:InventorySource.RunningProcess);await f.Inventory.ApplyAsync(await f.AppendAsync(start),DateTimeOffset.UtcNow);
        var stop=start with{Id=Guid.NewGuid(),Kind=InventoryRecordKind.ProcessStopped,Artifact=new("proc.exe",ProcessId:42,ProcessInstanceId:instance)};
        await f.Inventory.ApplyAsync(await f.AppendAsync(stop),DateTimeOffset.UtcNow);var stored=Assert.Single((await f.Inventory.ReadAsync(f.Node,f.LedgerId)).Items).Observation.Artifact!;
        Assert.False(stored.ReportedRunning);Assert.Equal(a.ProductVersion,stored.ProductVersion);Assert.Equal(a.MetadataUtc,stored.MetadataUtc);
        await f.Inventory.ApplyAsync(await f.AppendAsync(start with{Id=Guid.NewGuid(),Artifact=a with{ProcessInstanceId=Guid.NewGuid()}}),DateTimeOffset.UtcNow);
        Assert.Equal(2,(await f.Inventory.ReadAsync(f.Node,f.LedgerId)).Items.Length);
    }
    [Fact]
    public async Task IntelligencePagesResumeAcrossRestartAndFailedRefreshRetainsPublishedSnapshot()
    {
        using var temp=new TestLedger();string path=Path.Combine(temp.DirectoryPath,"exposure.db");var mapping=SoftwareEvidence.Mapping();var cve=SoftwareEvidence.Cve();
        await using(var first=SqliteExposureStore.Open(path))
        {await first.ReviewAsync(mapping);await first.StorePageAsync(mapping,0,[cve],2,DateTimeOffset.UtcNow,TimeSpan.FromHours(6));Assert.False((await first.ReadSnapshotAsync(mapping)).Complete);}
        await using var second=SqliteExposureStore.Open(path);Assert.Equal(1,(await second.ReadProgressAsync(mapping.Id))!.NextIndex);
        await second.StorePageAsync(mapping,1,[cve with{Id="CVE-2026-12346"}],2,DateTimeOffset.UtcNow,TimeSpan.FromHours(6));Assert.Equal(2,(await second.ReadSnapshotAsync(mapping)).Records.Length);
        await second.FailRefreshAsync(mapping,DateTimeOffset.UtcNow);var failed=await second.ReadSnapshotAsync(mapping);Assert.Equal("RefreshFailed",failed.Error);Assert.Equal(2,failed.Records.Length);
        await Assert.ThrowsAsync<ArgumentException>(()=>second.ReviewAsync(mapping with{Product="Changed"}));
        await second.ReviewAsync(mapping with{Revision=2,Product="Changed"});Assert.Equal(2,(await second.ReadMappingHistoryAsync(mapping.Id)).Length);
        Assert.False((await second.ReadSnapshotAsync(mapping with{Revision=2})).Complete);
    }
    [Fact]
    public async Task ExposureEvaluationPreservesAlertsDuringOutageAndResolvesOnlyKnownVersionExclusions()
    {
        await using var f=await SoftwareFixture.CreateAsync();await using var exposures=SqliteExposureStore.Open(f.PathFor("exposure.db"));
        await using var alerts=await SqliteAlertStore.OpenAsync(new(){DatabasePath=f.PathFor("alerts.db")});var mapping=SoftwareEvidence.Mapping();await exposures.ReviewAsync(mapping);
        await exposures.StorePageAsync(mapping,0,[SoftwareEvidence.Cve()],1,DateTimeOffset.UtcNow,TimeSpan.FromHours(6));var item=SoftwareFixture.Record();await f.AppendAsync(item);
        using var runtime=new SoftwareRuntime(f.Ledger,f.Inventory,exposures,alerts,[new(f.Node,f.LedgerId)],new(){Enabled=true},null,NullLogger<SoftwareRuntime>.Instance);
        await runtime.RunOnceAsync();var affected=Assert.Single((await alerts.ReadAsync(new(ActiveOnly:true))).Alerts);Assert.Equal("SoftwareExposure",affected.Code);
        await alerts.ApplyAsync(new(f.Node,f.LedgerId,DateTimeOffset.UtcNow,[],true));Assert.Equal(1,(await alerts.CountAsync()).Open);
        await exposures.FailRefreshAsync(mapping,DateTimeOffset.UtcNow);await runtime.RunOnceAsync();Assert.Equal(2,(await alerts.CountAsync()).Open);
        Assert.Contains((await exposures.ReadFindingsAsync(f.Node,f.LedgerId)).Findings,x=>x.Applicability==Applicability.Unknown);
        await exposures.StorePageAsync(mapping,0,[SoftwareEvidence.Cve()],1,DateTimeOffset.UtcNow,TimeSpan.FromHours(6));
        await f.AppendAsync(item with{Id=Guid.NewGuid(),ScanId=Guid.NewGuid(),ObservedUtc=DateTimeOffset.UtcNow,Artifact=item.Artifact! with{ProductVersion="3.0"}});await runtime.RunOnceAsync();
        Assert.Equal(0,(await alerts.CountAsync()).Open);Assert.Equal(2,(await alerts.CountAsync()).Resolved);
        var finding=Assert.Single((await exposures.ReadFindingsAsync(f.Node,f.LedgerId)).Findings);Assert.Equal(Applicability.NotAffected,finding.Applicability);
        Assert.Equal(3,(await exposures.ReadHistoryAsync(finding.Id)).Length);
        await runtime.RunOnceAsync();Assert.Equal(3,(await exposures.ReadHistoryAsync(finding.Id)).Length);
    }
    [Fact]
    public async Task ExposureAlertsUseTheExistingDurableNotificationFeedAndPreserveSubject()
    {
        await using var f=await NotificationFixture.CreateAsync();string prefix=new('A',64);string subject=prefix+":CVE-2026-12345";
        await f.Operations.Alerts.ApplyAsync(new(f.Operations.NodeId,f.Operations.LedgerId,f.Clock.GetUtcNow(),[new("SoftwareExposure",AlertSeverity.Warning,subject)],true,AlertCategory.Exposure,prefix));
        await f.Dispatcher.RunOnceAsync();Assert.Single(f.Transport.Sent);var transition=Assert.Single((await f.Operations.Alerts.ReadChangesAsync(0)).Changes);
        Assert.Equal(AlertCategory.Exposure,transition.Alert.Category);Assert.Equal(subject,transition.Alert.Subject);
        Assert.Contains(subject,System.Text.Encoding.UTF8.GetString(f.Transport.Sent[0].Body));
    }
}
