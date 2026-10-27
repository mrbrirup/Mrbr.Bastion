using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Core;
using Mrbr.Bastion.Inventory.Agent;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Inventory.Crawling;
using Mrbr.Bastion.Inventory.Discovery;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Inventory.Windows;
using Mrbr.Bastion.Transport;
using Mrbr.Bastion.Transport.Http;
using Mrbr.Bastion.Transport.Grpc;

if(args.Length==0||args.Contains("--help"))
{Console.WriteLine("Usage: Mrbr.Bastion.Inventory.Agent <settings.json> [--inspect|--once|--send-only] [--new-scan]\nInitialize with --inspect, enroll the printed ledger ID, then collect or deliver. --new-scan restarts completed crawler tasks; unfinished tasks resume. Collection is passive; optional process ETW requires elevation. Ctrl+C stops collection; pending evidence remains durable.");return 0;}
if(args.Length>3||args.Skip(1).Any(a=>a is not("--inspect" or "--once" or "--send-only" or "--new-scan"))||args.Skip(1).Distinct().Count()!=args.Length-1||args.Skip(1).Count(a=>a is "--inspect" or "--once" or "--send-only")>1||args.Contains("--new-scan")&&(args.Contains("--inspect")||args.Contains("--send-only"))){Console.Error.WriteLine("Use --help for usage.");return 1;}
bool inspect=args.Contains("--inspect"),once=args.Contains("--once"),sendOnly=args.Contains("--send-only");
try
{
    string root=Path.GetDirectoryName(Path.GetFullPath(args[0]))!;
    var settings=JsonSerializer.Deserialize<InventoryAgentSettings>(await File.ReadAllTextAsync(args[0]),InventoryJson.Options)??throw new InvalidDataException("Inventory settings missing.");settings.Validate();
    string Resolve(string p)=>Path.GetFullPath(p,root);
    string cachePath=Resolve(settings.CacheDatabasePath);
    if(sendOnly&&!File.Exists(cachePath))throw new FileNotFoundException("The existing inventory outbox is missing.");
    if(sendOnly&&settings.ServiceUri is null)throw new ArgumentException("Send-only requires a receiver address.");
    using var nodeKey=ECDsa.Create();nodeKey.ImportFromPem(await File.ReadAllTextAsync(Resolve(settings.NodePrivateKeyPath)));
    using var receiverKey=ECDsa.Create();receiverKey.ImportFromPem(await File.ReadAllTextAsync(Resolve(settings.ReceiverPublicKeyPath)));
    using var node=new EcdsaSignatureProvider(nodeKey,Convert.ToHexString(SHA256.HashData(nodeKey.ExportSubjectPublicKeyInfo())));
    using var receiver=new EcdsaSignatureProvider(receiverKey,Convert.ToHexString(SHA256.HashData(receiverKey.ExportSubjectPublicKeyInfo())));
    await using var cache=await DurableTelemetryCache.OpenAsync(new(){NodeId=settings.NodeId,DatabasePath=cachePath,AdditionalPayloadCodecs=[new InventoryPayloadCodec()],MaximumStoredPayloadBytes=settings.MaximumStoredPayloadBytes,Retention=settings.Retention},node,node,receiver);
    Console.WriteLine($"Inventory outbox: {(await cache.GetStatusAsync()).Checkpoint}");if(inspect)return 0;
    using var stop=new CancellationTokenSource();
    await using var desktopControl=Mrbr.Bastion.Hosting.LocalProcessControl.FromEnvironment(stop.Cancel);
    ConsoleCancelEventHandler cancel=(_,e)=>{e.Cancel=true;stop.Cancel();};Console.CancelKeyPress+=cancel;
    try
    {
        var transportOptions=new TelemetryTransportOptions{AllowInsecureLoopback=settings.AllowInsecureLoopback};Uri? address=settings.ServiceUri is null?null:new Uri(settings.ServiceUri);if(address is not null)transportOptions.ValidateAddress(address);
        using var http=address is not null&&settings.Transport=="http"?new HttpTelemetryTransport(address,receiver,transportOptions):null;
        await using var grpc=address is not null&&settings.Transport=="grpc"?new GrpcTelemetryTransport(address,receiver,transportOptions):null;
        ITelemetryTransport? transport=http is not null?http:grpc;
        var dispatcher=transport is null?null:new TelemetryDispatcher(cache,transport);
        async Task Deliver(bool continuous,CancellationToken ct)
        {
            using var client=new HttpClient(new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=false}){Timeout=TimeSpan.FromSeconds(30)};
            while(true)
            {
                try
                {
                    using var request=new HttpRequestMessage(HttpMethod.Get,new Uri(new Uri(address!.AbsoluteUri.TrimEnd('/')+"/"),"api/v1/telemetry/capabilities"));
                    if(settings.Transport=="grpc"){request.Version=new Version(2,0);request.VersionPolicy=HttpVersionPolicy.RequestVersionExact;}
                    using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,ct);response.EnsureSuccessStatusCode();
                    using var stream=await response.Content.ReadAsStreamAsync(ct);using var data=new MemoryStream();var buffer=new byte[1024];int n;
                    while((n=await stream.ReadAsync(buffer,ct))>0){if(data.Length+n>4096)throw new InvalidDataException("Receiver capabilities exceeded their budget.");data.Write(buffer,0,n);}
                    using var doc=JsonDocument.Parse(data.ToArray());
                    if(!doc.RootElement.GetProperty("payloadFormats").EnumerateArray().Any(p=>p.GetString()==LedgerProtocol.InventoryPayloadFormat))throw new InvalidDataException("The receiver has not enabled inventory ingestion.");break;
                }
                catch(HttpRequestException)when(continuous&&!ct.IsCancellationRequested){Console.Error.WriteLine("Inventory receiver unavailable; evidence remains in the local outbox.");await Task.Delay(TimeSpan.FromSeconds(30),ct);}
            }
            if(continuous)await dispatcher!.RunAsync(ct);else while(await dispatcher!.DispatchPendingAsync(ct)>0){}
        }
        if(sendOnly){await Deliver(false,stop.Token);Console.WriteLine($"Delivery: {dispatcher!.GetHealth()}");if(settings.Retention.Enabled)Console.WriteLine($"Retention: {await cache.ApplyRetentionAsync(stop.Token)}");return 0;}
        if((settings.Processes||settings.InstalledApplications||settings.ProcessEvents)&&!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Disable Windows discovery sources to run a file-only inventory agent on this platform.");
        if(settings.Retention.Enabled)Console.WriteLine($"Initial retention: {await cache.ApplyRetentionAsync(stop.Token)}");
        async Task Publish(InventoryRecord row,CancellationToken ct){await cache.AppendPayloadAsync(LedgerProtocol.InventoryPayloadFormat,InventoryJson.Encode([row]),1,ct);}
        var inspector=new ArtifactInspector();var windows=new WindowsInventorySource(inspector);
        async Task Baseline(CancellationToken ct)
        {
            do
            {
                if(settings.Processes)await foreach(var row in windows.ProcessesAsync(ct))await Publish(row,ct);
                if(settings.InstalledApplications)foreach(var row in windows.Installed(settings.IncludeCurrentUser))await Publish(row,ct);
                if(once)return;await Task.Delay(TimeSpan.FromSeconds(settings.BaselineSeconds),ct);
            }while(!ct.IsCancellationRequested);
        }
        await using var journal=SqliteCrawlerJournal.Open(Resolve(settings.CrawlerDatabasePath));
        var crawlers=settings.Crawlers.Where(t=>t.Enabled).OrderByDescending(t=>t.Priority).Select(t=>(Task:t,Crawler:new InventoryCrawler(journal,inspector))).ToArray();
        if(args.Contains("--new-scan"))foreach(var item in crawlers)if((await journal.InitializeAsync(item.Task,stop.Token)).Finished)await journal.RestartCompletedAsync(item.Task,stop.Token);
        async Task Crawl(CancellationToken ct)
        {
            while(true)
            {
                await Parallel.ForEachAsync(crawlers,new ParallelOptions{MaxDegreeOfParallelism=settings.MaximumConcurrentCrawlers,CancellationToken=ct},async(item,token)=>{await item.Crawler.RunRoundAsync(item.Task,Publish,token);});
                bool done=true;foreach(var item in crawlers)done&=(await journal.StateAsync(item.Task.Id,ct)).Finished;
                if(done)
                {
                    if(once||settings.CrawlRepeatSeconds==0||crawlers.Length==0)return;
                    await Task.Delay(TimeSpan.FromSeconds(settings.CrawlRepeatSeconds),ct);
                    foreach(var item in crawlers)await journal.RestartCompletedAsync(item.Task,ct);
                }
            }
        }
        async Task Enrich(CancellationToken ct)
        {
            if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
            var source=new WindowsEtwTelemetrySource(new(){CollectFileEvents=false});
            await new ProcessEnrichmentWorker(source,windows.EnrichProcessEventAsync,Publish,settings.EnrichmentQueueCapacity).RunAsync(ct);
        }
        if(once){await Task.WhenAll(Baseline(stop.Token),Crawl(stop.Token));if(dispatcher is not null)await Deliver(false,stop.Token);if(settings.Retention.Enabled)Console.WriteLine($"Retention: {await cache.ApplyRetentionAsync(stop.Token)}");}
        else
        {
            var tasks=new List<Task>{Baseline(stop.Token),Crawl(stop.Token)};if(settings.ProcessEvents)tasks.Add(Enrich(stop.Token));if(dispatcher is not null)tasks.Add(Deliver(true,stop.Token));
            if(settings.Retention.Enabled)tasks.Add(cache.RunRetentionAsync(message=>Console.WriteLine("Retention: "+message),stop.Token));
            var pending=new List<Task>(tasks);try{while(pending.Count>0){var finished=await Task.WhenAny(pending);await finished;pending.Remove(finished);}}finally{await stop.CancelAsync();try{await Task.WhenAll(tasks);}catch(OperationCanceledException)when(stop.IsCancellationRequested){}}
        }
        Console.WriteLine($"Inventory captured. Pending blocks: {(await cache.GetStatusAsync()).PendingBlocks}");return 0;
    }catch(OperationCanceledException)when(stop.IsCancellationRequested){Console.WriteLine("Stopped. Pending inventory remains in the durable outbox.");return 0;}
    finally{Console.CancelKeyPress-=cancel;}
}
catch(Exception e){Console.Error.WriteLine(e.Message);return 1;}
