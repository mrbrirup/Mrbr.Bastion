using System.Threading.Channels;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Inventory.Contracts;

namespace Mrbr.Bastion.Inventory.Agent;

/// <summary>Keeps metadata I/O off ETW callbacks and reports bounded queue loss separately from source loss.</summary>
public sealed class ProcessEnrichmentWorker(ITelemetrySource source,Func<TelemetryEvent,CancellationToken,Task<InventoryRecord?>> enrich,
    Func<InventoryRecord,CancellationToken,Task> publish,int capacity=1024)
{
    private int _started;private long _dropped,_inFlight;
    public long Dropped=>Interlocked.Read(ref _dropped);
    public async Task RunAsync(CancellationToken cancellationToken=default)
    {
        if(capacity is <1 or >10000)throw new ArgumentOutOfRangeException(nameof(capacity));
        if(Interlocked.Exchange(ref _started,1)!=0)throw new InvalidOperationException("An enrichment worker can only run once.");
        using var lifetime=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);var ct=lifetime.Token;
        var queue=Channel.CreateBounded<TelemetryEvent>(new BoundedChannelOptions(capacity){FullMode=BoundedChannelFullMode.Wait,SingleReader=true,SingleWriter=true});
        Guid run=Guid.NewGuid();long reportedDropped=0,reportedLost=0;
        InventoryRecord Coverage(string code,string location)=>new(1,Guid.NewGuid(),run,"process-events",InventorySource.RunningProcess,InventoryRecordKind.Coverage,DateTimeOffset.UtcNow,"process-events",Coverage:new(code,location));
        async Task Producer(){try{await source.RunAsync(e=>{if(!queue.Writer.TryWrite(e))Interlocked.Increment(ref _dropped);},ct);}finally{queue.Writer.TryComplete();}}
        async Task Consumer()
        {
            // Stop the producer on cancellation, then finish every observation already accepted.
            // Shutdown must not cancel its enrichment or the final durable outbox commit.
            await foreach(var item in queue.Reader.ReadAllAsync())
            {
                Interlocked.Exchange(ref _inFlight,1);InventoryRecord row;
                try{row=await enrich(item,CancellationToken.None)??Coverage("ProcessIdentityUnavailable",$"pid:{item.ProcessId}");}
                catch(Exception e)when(e is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException or ArgumentException)
                {row=Coverage("ProcessEnrichmentUnavailable",$"pid:{item.ProcessId}");}
                await publish(row,CancellationToken.None);Interlocked.Exchange(ref _inFlight,0);
            }
        }
        async Task Loss(CancellationToken token)
        {
            long lost=source.EventsLost,count=Dropped;
            if(count!=reportedDropped||lost!=reportedLost){await publish(Coverage("ProcessEventsLost",$"queue:{count};etw:{lost}"),token);reportedDropped=count;reportedLost=lost;}
        }
        async Task Ticker(){using var timer=new PeriodicTimer(TimeSpan.FromSeconds(5));while(await timer.WaitForNextTickAsync(ct))await Loss(ct);}
        var producer=Producer();var consumer=Consumer();var ticker=Ticker();
        try
        {
            var first=await Task.WhenAny(producer,consumer,ticker);await first;
            if(first==producer)await consumer;
        }
        finally
        {
            await lifetime.CancelAsync();
            try{await Task.WhenAll(producer,consumer,ticker);}catch(OperationCanceledException)when(ct.IsCancellationRequested){}
            using var final=new CancellationTokenSource(TimeSpan.FromSeconds(5));await Loss(final.Token);
            long pending=queue.Reader.Count+Interlocked.Read(ref _inFlight);
            if(pending>0)await publish(Coverage("ProcessEnrichmentStoppedWithPendingWork",$"pending:{pending}"),final.Token);
        }
    }
}
