using Mrbr.Bastion.Inventory.Contracts;

namespace Mrbr.Bastion.Inventory.Crawling;

public sealed class InventoryCrawler(ICrawlerJournal journal,IArtifactInspector inspector)
{
    private readonly SemaphoreSlim _run=new(1,1);
    public async Task<CrawlerState> RunRoundAsync(CrawlerTask task,Func<InventoryRecord,CancellationToken,Task> publish,CancellationToken cancellationToken=default)
    {
        await _run.WaitAsync(cancellationToken);
        try
        {
            var sink=publish;publish=async(record,token)=>{try{await sink(record,token);}catch(Exception error)when(error is not OperationCanceledException){throw new PublicationFailure(error);}};
            var state=await journal.InitializeAsync(task,cancellationToken);if(state.Finished)return state;
            InventoryRecord Row(InventoryRecordKind kind,SoftwareArtifact? artifact=null,InventoryCoverage? issue=null,bool complete=false,InventorySource source=InventorySource.FileSystem)=>
                new(1,Guid.NewGuid(),state.ScanId,task.Id,source,kind,DateTimeOffset.UtcNow,Path.GetFullPath(task.Root),artifact,issue is null?null:issue with{Location=InventoryJson.BoundedLocation(issue.Location)},complete);
            if(!state.Started){await publish(Row(InventoryRecordKind.ScanStarted),cancellationToken);await journal.MarkStartedAsync(task.Id,cancellationToken);}
            for(int n=0;n<task.WorkPerRound;n++)
            {
                cancellationToken.ThrowIfCancellationRequested();var work=await journal.NextAsync(task.Id,cancellationToken);if(work is null)break;bool partial=false;
                try
                {
                    string path=Path.GetFullPath(work.Path),root=Path.GetFullPath(task.Root);
                    if(!Inside(root,path))throw new IOException("OutOfScopePath");
                    if(path.Length>4096)throw new IOException("PathEvidenceBudgetExceeded");
                    for(string? ancestor=Path.GetDirectoryName(path);ancestor is not null&&Inside(root,ancestor);ancestor=Path.GetDirectoryName(ancestor))
                        if((File.GetAttributes(ancestor)&FileAttributes.ReparsePoint)!=0)throw new IOException("ReparsePointSkipped");
                    var attributes=File.GetAttributes(path);
                    if((attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("ReparsePointSkipped");
                    if((attributes&FileAttributes.Directory)!=0)
                    {
                        if(!task.ExcludedDirectories.Any(ex=>Inside(Path.GetFullPath(ex),path)))
                        foreach(var child in Directory.EnumerateFileSystemEntries(path))
                        {cancellationToken.ThrowIfCancellationRequested();await journal.EnqueueAsync(task.Id,child,task.MaximumWorkItems,cancellationToken);}
                        else {partial=true;await publish(Row(InventoryRecordKind.Coverage,issue:new("ConfiguredExclusion",path)),cancellationToken);}
                    }
                    else if(task.Extensions.Contains(Path.GetExtension(path),StringComparer.OrdinalIgnoreCase))
                    {
                        await publish(Row(InventoryRecordKind.Software,await inspector.InspectAsync(path,cancellationToken)),cancellationToken);
                        if(ArchiveInventory.IsArchive(path))
                        {
                            var archive=new ArchiveInventory(inspector,task);
                            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);timeout.CancelAfter(TimeSpan.FromSeconds(task.MaximumArchiveSeconds));
                            try
                            {
                                await foreach(var record in archive.ReadAsync(path,timeout.Token))
                                {if(record.Issue is not null)partial=true;await publish(record.Issue is {} issue?Row(InventoryRecordKind.Coverage,issue:issue,source:InventorySource.Archive):Row(InventoryRecordKind.Software,record.Artifact,source:InventorySource.Archive),cancellationToken);}
                            }
                            catch(OperationCanceledException)when(!cancellationToken.IsCancellationRequested)
                            {partial=true;await publish(Row(InventoryRecordKind.Coverage,issue:new("ArchiveTimeBudgetExceeded",path)),cancellationToken);}
                        }
                    }
                }
                catch(OperationCanceledException){throw;}
                catch(Exception e)when(e is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidDataException)
                {
                    partial=true;string code=e is UnauthorizedAccessException?"AccessDenied":e.Message is "ReparsePointSkipped" or "OutOfScopePath" or "CrawlerWorkBudgetExceeded" or "FileByteBudgetExceeded" or "FileChangedDuringRead"?e.Message:"PathUnavailable";
                    await publish(Row(InventoryRecordKind.Coverage,issue:new(code,work.Path)),cancellationToken);
                }
                // Publish first. A crash before this checkpoint causes an observable, safe re-read rather than data loss.
                await journal.FinishWorkAsync(task.Id,work.Id,partial,cancellationToken);
                if(task.DelayMilliseconds>0)await Task.Delay(task.DelayMilliseconds,cancellationToken);
            }
            state=await journal.StateAsync(task.Id,cancellationToken);
            await publish(Row(InventoryRecordKind.ScanProgress) with{Progress=new(state.Pending,state.Completed)},cancellationToken);
            if(state.Pending==0)
            {await publish(Row(InventoryRecordKind.ScanCompleted,complete:!state.Partial),cancellationToken);await journal.FinishAsync(task.Id,cancellationToken);state=await journal.StateAsync(task.Id,cancellationToken);}
            return state;
        }
        catch(PublicationFailure failure){System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure.InnerException!).Throw();throw;}
        finally{_run.Release();}
    }
    private sealed class PublicationFailure(Exception cause):Exception("Inventory publication failed.",cause);
    public static bool Inside(string root,string path)=>string.Equals(root.TrimEnd(Path.DirectorySeparatorChar),path.TrimEnd(Path.DirectorySeparatorChar),OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal)
        || path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar,OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal);
}
