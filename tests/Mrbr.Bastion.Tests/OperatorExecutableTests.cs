using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.Security;
using Mrbr.Bastion.Operators.Sqlite;
using Mrbr.Bastion.Server;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class OperatorExecutableTests
{
    [Fact]
    public async Task ProvisioningToolAndConfiguredServerUseDurableNamedUsersAcrossRestarts()
    {
        using var temp=new TestLedger();Directory.CreateDirectory(temp.DirectoryPath);string database=Path.Combine(temp.DirectoryPath,"operators.db");
        var bootstrap=await Tool("bootstrap",database,"fixture-admin");Assert.Equal(0,bootstrap.Code);Assert.DoesNotContain(OperatorFixture.Password,bootstrap.Output);
        Assert.Equal(1,(await Tool("bootstrap",database,"other-admin")).Code);
        File.WriteAllText(Path.Combine(temp.DirectoryPath,"node-public.pem"),temp.NodeKey.ExportSubjectPublicKeyInfoPem());File.WriteAllText(Path.Combine(temp.DirectoryPath,"receiver-private.pem"),temp.ServerKey.ExportPkcs8PrivateKeyPem());
        string config=Path.Combine(temp.DirectoryPath,"server.json");File.WriteAllText(config,JsonSerializer.Serialize(new
        {
            Kestrel=new{Endpoints=new{Test=new{Url="http://127.0.0.1:0",Protocols="Http1"}}},Bastion=new ServerSettings
            {
                DatabasePath="central.db",ReceiptSigningPrivateKeyPath="receiver-private.pem",AllowInsecureLoopback=true,
                Dashboard=new(){Enabled=true,OperatorDatabasePath="operators.db"},
                Nodes=[new(){NodeId="operator-fixture-node",LedgerId=Guid.NewGuid(),PublicKeys=[new(){Path="node-public.pem"}]}]
            }
        }));string? oldCookie=null;
        for(int restart=0;restart<2;restart++)
        {
            using var server=Start(typeof(ServerSettings).Assembly.Location,["--config",config]);var errors=server.StandardError.ReadToEndAsync();
            try
            {
                using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(20));Uri? address=null;
                while(address is null){string? line=await server.StandardOutput.ReadLineAsync(deadline.Token);if(line is null)throw new IOException("Named-user server startup failed: "+await errors);int index=line.IndexOf("Now listening on: ",StringComparison.Ordinal);if(index>=0)address=new(line[(index+18)..].Trim());}
                var output=server.StandardOutput.ReadToEndAsync();using var client=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){BaseAddress=address};
                if(oldCookie is not null){using var replay=new HttpRequestMessage(HttpMethod.Get,"/dashboard/api/operators");replay.Headers.Add("Cookie",oldCookie);Assert.Equal(HttpStatusCode.Unauthorized,(await client.SendAsync(replay)).StatusCode);}
                string form=await client.GetStringAsync("/dashboard/login");Assert.Contains("name=\"userName\"",form);Assert.DoesNotContain("name=\"accessToken\"",form);
                using var login=await client.PostAsync("/dashboard/login",new FormUrlEncodedContent(new Dictionary<string,string>{{"userName","fixture-admin"},{"password",OperatorFixture.Password},{"__RequestVerificationToken",DashboardTestHost.FormToken(form)}}));Assert.Equal(HttpStatusCode.Redirect,login.StatusCode);
                oldCookie=login.Headers.GetValues("Set-Cookie").Single(h=>h.StartsWith("Mrbr.Bastion.Operator=",StringComparison.Ordinal)).Split(';')[0];
                using var session=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/session"));Assert.Equal("fixture-admin",session.RootElement.GetProperty("operatorName").GetString());Assert.Equal("Users",session.RootElement.GetProperty("authenticationMode").GetString());
                using var users=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/operators"));Assert.Equal(restart==0?1:2,users.RootElement.GetProperty("users").GetArrayLength());
                if(restart==0){using var created=await OperatorFixture.PostAsync(client,"operators",new{userName="named-viewer",displayName="Named Viewer",roles=new[]{"Viewer"},password="temporary-viewer-password-value"});created.EnsureSuccessStatusCode();}
                else Assert.Contains("named-viewer",await client.GetStringAsync("/dashboard/api/operators"));
            }
            finally{if(!server.HasExited)server.Kill(entireProcessTree:true);await server.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));}
        }
        var recover=await Tool("recover-admin",database,"fixture-admin");Assert.Equal(0,recover.Code);
        await using var store=SqliteOperatorStore.Open(new(){DatabasePath=database});var recovered=await new OperatorAccounts(store).LoginAsync("fixture-admin",OperatorFixture.Password,null,TimeSpan.FromHours(8));Assert.NotNull(recovered);Assert.True(recovered.Account.MustChangePassword);
        Assert.Contains((await store.ReadSecurityAsync(limit:100)).Events,e=>e.Action=="AdministratorRecoveredLocally");
    }
    private static Process Start(string assembly,string[] args,bool input=false)
    {
        string tests=typeof(OperatorExecutableTests).Assembly.Location;var start=new ProcessStartInfo("dotnet"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,RedirectStandardInput=input};
        foreach(string arg in new[]{"exec","--runtimeconfig",Path.ChangeExtension(tests,"runtimeconfig.json"),"--depsfile",Path.ChangeExtension(tests,"deps.json"),assembly}.Concat(args))start.ArgumentList.Add(arg);
        foreach(string key in start.Environment.Keys.Where(k=>k.StartsWith("Bastion__",StringComparison.OrdinalIgnoreCase)||k.StartsWith("Kestrel__",StringComparison.OrdinalIgnoreCase)).ToArray())start.Environment.Remove(key);
        return Process.Start(start)!;
    }
    private static async Task<(int Code,string Output)> Tool(params string[] args)
    {
        using var child=Start(Path.Combine(AppContext.BaseDirectory,"Mrbr.Bastion.Operators.Tool.dll"),args.Concat(["--password-stdin"]).ToArray(),true);var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();
        try{await child.StandardInput.WriteLineAsync(OperatorFixture.Password);child.StandardInput.Close();await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));return(child.ExitCode,await stdout+await stderr);}
        finally{if(!child.HasExited){child.Kill(entireProcessTree:true);await child.WaitForExitAsync();}}
    }
}
