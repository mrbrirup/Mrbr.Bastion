using Mrbr.Bastion.Inventory.Agent;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Inventory.Crawling;
using Mrbr.Bastion.Inventory.Discovery;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Vulnerabilities;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class SoftwareRecoveryTests
{
    [Fact]
    public async Task GracefulEnrichmentStopDrainsQueuedAndInFlightObservations()
    {
        var accepted=Enumerable.Range(1,3).Select(pid=>TestLedger.Event(pid)).ToArray();
        var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var rows=new List<InventoryRecord>();int calls=0;bool sourceStopped=false;
        using var stop=new CancellationTokenSource();
        var source=new DelegateSource(async(callback,ct)=>
        {
            try{foreach(var item in accepted)callback(item);await Task.Delay(Timeout.Infinite,ct);}
            finally{sourceStopped=true;}
        });
        var worker=new ProcessEnrichmentWorker(source,async(item,ct)=>
        {
            if(Interlocked.Increment(ref calls)==1){entered.SetResult();await resume.Task.WaitAsync(ct);}
            ct.ThrowIfCancellationRequested();return SoftwareFixture.Record() with{Id=item.EventId};
        },(row,ct)=>{ct.ThrowIfCancellationRequested();rows.Add(row);return Task.CompletedTask;},capacity:4);
        var running=worker.RunAsync(stop.Token);
        try{await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));await stop.CancelAsync();}
        finally{resume.TrySetResult();}
        try{await running.WaitAsync(TimeSpan.FromSeconds(5));}
        catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        Assert.True(sourceStopped);Assert.Equal(0,worker.Dropped);
        Assert.Equal(accepted.Select(e=>e.EventId),rows.Select(r=>r.Id));
        Assert.DoesNotContain(rows,r=>r.Coverage?.Code=="ProcessEnrichmentStoppedWithPendingWork");
    }

    [Fact]
    public async Task EnrichmentCallbacksStayNonblockingAndPersistLossEvidence()
    {
        var rows=new List<InventoryRecord>();var source=new DelegateSource((callback,_)=>{for(int i=0;i<100;i++)callback(TestLedger.Event(i));return Task.CompletedTask;},eventsLost:3);
        var worker=new ProcessEnrichmentWorker(source,(_,_)=>Task.FromResult<InventoryRecord?>(SoftwareFixture.Record()),(row,_)=>{rows.Add(row);return Task.CompletedTask;},capacity:1);
        await worker.RunAsync();Assert.Equal(99,worker.Dropped);Assert.Contains(rows,r=>r.Coverage?.Code=="ProcessEventsLost"&&r.Coverage.Location=="queue:99;etw:3");Assert.Single(rows,r=>r.Kind==InventoryRecordKind.Software);
    }
    [Fact]
    public async Task PublicationFailureStopsTheEnrichmentSourceAndNeverBecomesAMetadataCoverageFailure()
    {
        bool stopped=false;var source=new DelegateSource(async(callback,ct)=>{try{callback(TestLedger.Event());await Task.Delay(Timeout.Infinite,ct);}finally{stopped=true;}});
        var worker=new ProcessEnrichmentWorker(source,(_,_)=>Task.FromResult<InventoryRecord?>(SoftwareFixture.Record()),(_,_)=>throw new IOException("outbox unavailable"));
        await Assert.ThrowsAsync<IOException>(()=>worker.RunAsync().WaitAsync(TimeSpan.FromSeconds(5)));Assert.True(stopped);
    }
    [Fact]
    public async Task RepeatedScansKeepStableIdentityAndCanConfirmRemovalWithinAnUnchangedScope()
    {
        await using var f=await SoftwareFixture.CreateAsync();string root=f.PathFor("files");Directory.CreateDirectory(root);string file=Path.Combine(root,"sample.exe");File.WriteAllText(file,"fixture");
        await using var journal=SqliteCrawlerJournal.Open(f.PathFor("crawlers.db"));var task=new CrawlerTask{Id="files",Root=root,DelayMilliseconds=0};var crawler=new InventoryCrawler(journal,new ArtifactInspector());
        async Task Save(InventoryRecord row,CancellationToken _){var b=await f.AppendAsync(row);await f.Inventory.ApplyAsync(b,DateTimeOffset.UtcNow);}
        var first=await crawler.RunRoundAsync(task,Save);Assert.True(first.Finished);var before=Assert.Single((await f.Inventory.ReadAsync(f.Node,f.LedgerId)).Items);
        File.Delete(file);await journal.RestartCompletedAsync(task);var second=await crawler.RunRoundAsync(task,Save);Assert.NotEqual(first.ScanId,second.ScanId);var after=Assert.Single((await f.Inventory.ReadAsync(f.Node,f.LedgerId)).Items);
        Assert.Equal(before.Key,after.Key);Assert.True(after.Missing);Assert.NotNull(after.MissingConfirmedUtc);
        var correlator=new ExposureCorrelator(TimeSpan.FromDays(1),TimeSpan.FromDays(1));Assert.True(correlator.IsConfirmedAbsent(after,DateTimeOffset.UtcNow));
        Assert.False(correlator.IsConfirmedAbsent(after,DateTimeOffset.UtcNow.AddDays(2)));
    }
    [Fact]
    public async Task OldResumedScansCannotPresentFreshAbsenceEvidence()
    {
        await using var f=await SoftwareFixture.CreateAsync();await f.Inventory.ApplyAsync(await f.AppendAsync(SoftwareFixture.Record()),DateTimeOffset.UtcNow);Guid scan=Guid.NewGuid();
        await f.Inventory.ApplyAsync(await f.AppendAsync(SoftwareFixture.Record(InventoryRecordKind.ScanStarted,scan) with{ObservedUtc=DateTimeOffset.UtcNow.AddDays(-2)}),DateTimeOffset.UtcNow);
        await f.Inventory.ApplyAsync(await f.AppendAsync(SoftwareFixture.Record(InventoryRecordKind.ScanCompleted,scan,complete:true)),DateTimeOffset.UtcNow);
        var missing=Assert.Single((await f.Inventory.ReadAsync(f.Node,f.LedgerId)).Items);Assert.True(missing.Missing);
        Assert.False(new ExposureCorrelator(TimeSpan.FromDays(1),TimeSpan.FromDays(1)).IsConfirmedAbsent(missing,DateTimeOffset.UtcNow));
    }
    [Fact]
    public async Task ATransientPublicationFailureCannotAdvanceCrawlerWorkAsIfAFileWasUnreadable()
    {
        using var temp=new TestLedger();string root=Path.Combine(temp.DirectoryPath,"files");Directory.CreateDirectory(root);File.WriteAllText(Path.Combine(root,"sample.exe"),"fixture");
        await using var journal=SqliteCrawlerJournal.Open(Path.Combine(temp.DirectoryPath,"crawler.db"));var crawler=new InventoryCrawler(journal,new ArtifactInspector());var task=new CrawlerTask{Id="files",Root=root,WorkPerRound=1,DelayMilliseconds=0};
        await crawler.RunRoundAsync(task,(_,_)=>Task.CompletedTask);int attempts=0;
        await Assert.ThrowsAsync<IOException>(()=>crawler.RunRoundAsync(task,(_,_)=>++attempts==1?throw new IOException("temporary publication failure"):Task.CompletedTask));
        Assert.Equal(1,attempts);Assert.Equal(1,(await journal.StateAsync(task.Id)).Pending);Assert.False((await journal.StateAsync(task.Id)).Partial);
    }
    [Fact]
    public async Task ConfirmedSeverityChangesCreateANewLifecycleWhileUnknownEvidencePreservesCriticalSeverity()
    {
        await using var f=await NotificationFixture.CreateAsync();string prefix=new('A',64);string subject=prefix+":CVE-2026-12345";
        async Task Observe(Mrbr.Bastion.Alerting.AlertSeverity severity,bool preserve=false)=>await f.Operations.Alerts.ApplyAsync(new(f.Operations.NodeId,f.Operations.LedgerId,f.Clock.GetUtcNow(),[new("SoftwareExposure",severity,subject,preserve)],true,Mrbr.Bastion.Alerting.AlertCategory.Exposure,prefix));
        await Observe(Mrbr.Bastion.Alerting.AlertSeverity.Warning);f.Clock.Advance(TimeSpan.FromSeconds(1));await Observe(Mrbr.Bastion.Alerting.AlertSeverity.Critical);
        var transitions=(await f.Operations.Alerts.ReadChangesAsync(0)).Changes;Assert.Equal(3,transitions.Length);Assert.Equal(Mrbr.Bastion.Alerting.AlertEventKind.Resolved,transitions[1].Event.Kind);
        Assert.Equal(Mrbr.Bastion.Alerting.AlertSeverity.Critical,transitions[2].Alert.Severity);Assert.NotEqual(transitions[0].Alert.Id,transitions[2].Alert.Id);
        f.Clock.Advance(TimeSpan.FromSeconds(1));await Observe(Mrbr.Bastion.Alerting.AlertSeverity.Warning,preserve:true);
        Assert.Equal(Mrbr.Bastion.Alerting.AlertSeverity.Critical,Assert.Single((await f.Operations.Alerts.ReadAsync(new(ActiveOnly:true))).Alerts).Severity);
        Assert.Equal(3,(await f.Operations.Alerts.ReadChangesAsync(0)).Changes.Length);
    }
}
