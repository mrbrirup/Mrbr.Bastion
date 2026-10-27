using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Inventory.Agent;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Inventory.Discovery;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Server;
using Mrbr.Bastion.Software.Hosting;
using Mrbr.Bastion.Vulnerabilities;
using Mrbr.Bastion.Vulnerabilities.Sqlite;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class SoftwareExecutableTests
{
    [Fact]
    public async Task OfflineAgentCaptureDeliversToConfiguredServerAndSurvivesServerRestart()
    {
        using var temp=new TestLedger();Directory.CreateDirectory(temp.DirectoryPath);string root=Path.Combine(temp.DirectoryPath,"files");Directory.CreateDirectory(root);
        string sample=Path.Combine(root,"sample.dll");File.Copy(typeof(SoftwareExecutableTests).Assembly.Location,sample);
        File.WriteAllText(Path.Combine(temp.DirectoryPath,"node.pem"),temp.NodeKey.ExportPkcs8PrivateKeyPem());File.WriteAllText(Path.Combine(temp.DirectoryPath,"node-public.pem"),temp.NodeKey.ExportSubjectPublicKeyInfoPem());
        File.WriteAllText(Path.Combine(temp.DirectoryPath,"receiver.pem"),temp.ServerKey.ExportPkcs8PrivateKeyPem());File.WriteAllText(Path.Combine(temp.DirectoryPath,"receiver-public.pem"),temp.ServerKey.ExportSubjectPublicKeyInfoPem());
        var agent=new InventoryAgentSettings{NodeId="inventory-process-fixture",CacheDatabasePath="agent.db",CrawlerDatabasePath="crawlers.db",NodePrivateKeyPath="node.pem",ReceiverPublicKeyPath="receiver-public.pem",Processes=false,InstalledApplications=false,Crawlers=[new(){Id="files",Root=root,DelayMilliseconds=0}]};
        string agentPath=Path.Combine(temp.DirectoryPath,"agent.json");void SaveAgent()=>File.WriteAllText(agentPath,JsonSerializer.Serialize(agent,InventoryJson.Options));SaveAgent();
        await RunAgent(agentPath,"--once");
        string nodeId=Convert.ToHexString(SHA256.HashData(temp.NodeKey.ExportSubjectPublicKeyInfo()));string receiptId=Convert.ToHexString(SHA256.HashData(temp.ServerKey.ExportSubjectPublicKeyInfo()));
        using var node=new EcdsaSignatureProvider(temp.NodeKey,nodeId);using var receiver=new EcdsaSignatureProvider(temp.ServerKey,receiptId);
        var cacheOptions=new DurableCacheOptions{NodeId=agent.NodeId,DatabasePath=Path.Combine(temp.DirectoryPath,"agent.db"),AdditionalPayloadCodecs=[new InventoryPayloadCodec()]};Guid ledgerId;
        await using(var cache=await DurableTelemetryCache.OpenAsync(cacheOptions,node,node,receiver)){ledgerId=(await cache.GetStatusAsync()).Checkpoint.LedgerId;Assert.True((await cache.GetStatusAsync()).PendingBlocks>=3);}
        string exposurePath=Path.Combine(temp.DirectoryPath,"exposures.db");var metadata=await new ArtifactInspector().InspectAsync(sample);
        // The copied test assembly has the release's informational version, including
        // prerelease/build metadata. Bind the synthetic advisory to that observed
        // version rather than assuming every future release is in the 1.x range.
        Assert.False(string.IsNullOrWhiteSpace(metadata.ProductVersion));
        var mapping=SoftwareEvidence.Mapping() with{Publisher=metadata.Publisher!,Product=metadata.Product!,Scheme=VersionScheme.Semantic};
        var advisory=SoftwareEvidence.Cve(start:metadata.ProductVersion,end:null);
        Assert.Equal(Applicability.Affected,ApplicabilityEvaluator.Evaluate(advisory,mapping,metadata.ProductVersion).State);
        await using(var exposures=SqliteExposureStore.Open(exposurePath)){await exposures.ReviewAsync(mapping);await exposures.StorePageAsync(mapping,0,[advisory],1,DateTimeOffset.UtcNow,TimeSpan.FromHours(6));}
        string serverPath=Path.Combine(temp.DirectoryPath,"server.json");File.WriteAllText(serverPath,JsonSerializer.Serialize(new
        {
            Kestrel=new{Endpoints=new{Test=new{Url="http://127.0.0.1:0",Protocols="Http1"}}},Bastion=new ServerSettings
            {
                DatabasePath="central.db",ReceiptSigningPrivateKeyPath="receiver.pem",AllowInsecureLoopback=true,
                Dashboard=new(){Enabled=true,AuthenticationMode=Mrbr.Bastion.Operators.AspNetCore.OperatorAuthenticationMode.LegacyToken,AccessToken=DashboardTestHost.Token,AlertEvaluationIntervalSeconds=1},
                Software=new SoftwareSettings{Enabled=true,InventoryDatabasePath="inventory.db",ExposureDatabasePath="exposures.db",PollSeconds=1},
                Nodes=[new(){NodeId=agent.NodeId,LedgerId=ledgerId,PublicKeys=[new(){Path="node-public.pem"}]}]
            }
        }));
        for(int restart=0;restart<2;restart++)
        {
            using var server=Start(typeof(ServerSettings).Assembly.Location,"--config",serverPath);var errors=server.StandardError.ReadToEndAsync();
            try
            {
                using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));Uri? address=null;
                while(address is null)
                {string? line=await server.StandardOutput.ReadLineAsync(deadline.Token);if(line is null)throw new IOException("Configured inventory server failed startup: "+await errors);int index=line.IndexOf("Now listening on: ",StringComparison.Ordinal);if(index>=0)address=new(line[(index+18)..].Trim());}
                var output=server.StandardOutput.ReadToEndAsync();
                agent.ServiceUri=address.AbsoluteUri;agent.AllowInsecureLoopback=true;SaveAgent();await RunAgent(agentPath,"--send-only");
                using var client=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){BaseAddress=address};
                using(var capabilities=JsonDocument.Parse(await client.GetStringAsync("/api/v1/telemetry/capabilities",deadline.Token)))Assert.Contains(capabilities.RootElement.GetProperty("payloadFormats").EnumerateArray(),p=>p.GetString()==Mrbr.Bastion.Abstraction.LedgerProtocol.InventoryPayloadFormat);
                await DashboardTestHost.LoginAsync(client);string scope=DashboardTestHost.Scope(agent.NodeId,ledgerId);bool affected=false;
                while(!affected)
                {using var page=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/exposures?"+scope,deadline.Token));affected=page.RootElement.GetProperty("findings").EnumerateArray().Any(x=>x.GetProperty("applicability").GetString()=="Affected");if(!affected)await Task.Delay(50,deadline.Token);}
                using var inventory=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/software?"+scope,deadline.Token));Assert.Equal(1,inventory.RootElement.GetProperty("items").GetArrayLength());
                await using var settled=await DurableTelemetryCache.OpenAsync(cacheOptions,node,node,receiver);Assert.Equal(0,(await settled.GetStatusAsync()).PendingBlocks);
            }
            finally{if(!server.HasExited)server.Kill(entireProcessTree:true);await server.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));}
        }
        await using var retained=SqliteInventoryStore.Open(Path.Combine(temp.DirectoryPath,"inventory.db"));Assert.Single((await retained.ReadAsync(agent.NodeId,ledgerId)).Items);
    }
    private static Process Start(string assembly,params string[] arguments)
    {
        string tests=typeof(SoftwareExecutableTests).Assembly.Location;var start=new ProcessStartInfo("dotnet"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(string argument in new[]{"exec","--runtimeconfig",Path.ChangeExtension(tests,"runtimeconfig.json"),"--depsfile",Path.ChangeExtension(tests,"deps.json"),assembly}.Concat(arguments))start.ArgumentList.Add(argument);
        foreach(string key in start.Environment.Keys.Where(k=>k.StartsWith("Bastion__",StringComparison.OrdinalIgnoreCase)||k.StartsWith("Kestrel__",StringComparison.OrdinalIgnoreCase)).ToArray())start.Environment.Remove(key);
        return Process.Start(start)!;
    }
    private static async Task RunAgent(string config,string mode)
    {
        using var child=Start(typeof(InventoryAgentSettings).Assembly.Location,config,mode);var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();
        try{await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));Assert.True(child.ExitCode==0,await stdout+await stderr);}
        finally{if(!child.HasExited){child.Kill(entireProcessTree:true);await child.WaitForExitAsync();}}
    }
}
