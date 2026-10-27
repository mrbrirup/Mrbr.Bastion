using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.Security;
using Mrbr.Bastion.Operators.Sqlite;

namespace Mrbr.Bastion.Tests;

internal sealed class OperatorFixture:IAsyncDisposable
{
    public const string Password="fixture-only-password-long-enough";
    public TestLedger Temp{get;}=new();
    public AuditClock Clock{get;}=new();
    public SqliteOperatorStore Store{get;private set;}=null!;
    public OperatorAccounts Accounts{get;private set;}=null!;
    public OperatorAccount Admin{get;private set;}=null!;
    public OperatorActor Actor{get;private set;}=null!;
    public string DatabasePath=>Path.Combine(Temp.DirectoryPath,"operators.db");
    public static async Task<OperatorFixture> CreateAsync(int maximumEvents=1000000)
    {
        var f=new OperatorFixture();try
        {
            f.Clock.SetUtc(DateTimeOffset.UtcNow);f.Store=SqliteOperatorStore.Open(new(){DatabasePath=f.DatabasePath,MaximumSecurityEvents=maximumEvents});
            f.Accounts=new(f.Store,clock:f.Clock);f.Admin=await f.Accounts.CreateAsync("admin","Fixture Administrator",[OperatorRole.Administrator],Password,bootstrap:true);
            f.Actor=new(f.Admin.Id,(await f.Store.FindByIdAsync(f.Admin.Id))!.SecurityStamp);return f;
        }catch{await f.DisposeAsync();throw;}
    }
    public Task<OperatorAccount> CreateUserAsync(string name,OperatorRole[] roles,bool mustChange=false)=>Store.CreateAsync(name,name,roles,new OperatorPasswords().Hash(Password),mustChange,Actor,false,Clock.GetUtcNow());
    public Task<OperatorSession?> LoginAsync(string name="admin",string password=Password)=>Accounts.LoginAsync(name,password,"127.0.0.1",TimeSpan.FromHours(8));
    public async Task ReopenAsync(){await Store.DisposeAsync();Store=SqliteOperatorStore.Open(new(){DatabasePath=DatabasePath});Accounts=new(Store,clock:Clock);}
    public async Task<DashboardTestHost> HostAsync(OperationsFixture operations)=>await DashboardTestHost.StartAsync(operations,configure:services=>
    {services.AddSingleton<IOperatorStore>(Store);services.AddSingleton(Accounts);services.AddSingleton<TimeProvider>(Clock);},dashboardOptions:new(){AllowInsecureLoopback=true});
    public static async Task LoginClientAsync(HttpClient client,string name="admin",string password=Password)
    {
        string csrf=DashboardTestHost.FormToken(await client.GetStringAsync("/dashboard/login"));using var response=await client.PostAsync("/dashboard/login",new FormUrlEncodedContent(new Dictionary<string,string>{{"userName",name},{"password",password},{"__RequestVerificationToken",csrf}}));
        Xunit.Assert.Equal(HttpStatusCode.Redirect,response.StatusCode);
    }
    public static async Task<HttpResponseMessage> PostAsync(HttpClient client,string path,object body,bool csrf=true)
    {
        using var request=new HttpRequestMessage(HttpMethod.Post,"/dashboard/api/"+path){Content=JsonContent.Create(body,options:OperatorValidation.Json)};
        if(csrf){using var session=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/session"));request.Headers.Add("X-CSRF-TOKEN",session.RootElement.GetProperty("csrfToken").GetString());}
        return await client.SendAsync(request);
    }
    public async ValueTask DisposeAsync(){if(Store is not null)await Store.DisposeAsync();Temp.Dispose();}
}
