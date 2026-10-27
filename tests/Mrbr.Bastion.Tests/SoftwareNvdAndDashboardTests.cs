using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Operations;
using Mrbr.Bastion.Vulnerabilities;
using Mrbr.Bastion.Vulnerabilities.Nvd;
using Mrbr.Bastion.Vulnerabilities.Sqlite;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class SoftwareNvdAndDashboardTests
{
    private const string CveJson="""
    {"id":"CVE-2026-12345","vulnStatus":"Analyzed","lastModified":"2026-10-25T12:00:00.000","descriptions":[{"lang":"en","value":"Fixture advisory"}],
     "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.8}}]},
     "configurations":[{"operator":"AND","nodes":[{"operator":"OR","negate":false,"cpeMatch":[{"criteria":"cpe:2.3:a:vendor:widget:*:*:*:*:*:*:*:*","vulnerable":true,"versionStartIncluding":"1.0.0","versionEndExcluding":"2.0.0"}]},{"operator":"OR","cpeMatch":[{"criteria":"cpe:2.3:o:vendor:os:10:*:*:*:*:*:*:*","vulnerable":false}]}]}]}
    """;
    [Fact]
    public async Task NvdAdapterPreservesRangesBooleanLogicAndSourceMetadataAndSendsOnlyReviewedIdentity()
    {
        var handler=new FixtureHandler(_=>new(HttpStatusCode.OK){Content=new StringContent("{\"startIndex\":0,\"totalResults\":1,\"vulnerabilities\":[{\"cve\":"+CveJson+"}]}",Encoding.UTF8,"application/json")});
        using var client=new NvdClient(handler,new("http://127.0.0.1/"),"fixture-key",true);var page=await client.FetchPageAsync(SoftwareEvidence.Mapping(),0,200);
        var cve=Assert.Single(page.Records);Assert.Equal(8.8,cve.Cvss);Assert.Equal(TimeSpan.Zero,cve.ModifiedUtc.Offset);Assert.Equal("AND",Assert.Single(cve.Configurations).Operator);
        Assert.Equal(Applicability.Unknown,ApplicabilityEvaluator.Evaluate(cve,SoftwareEvidence.Mapping(),"1.2.0").State);
        Assert.Equal(Applicability.Affected,ApplicabilityEvaluator.Evaluate(cve,SoftwareEvidence.Mapping(),"1.2.0",["cpe:2.3:o:vendor:os:10:*:*:*:*:*:*:*"]).State);
        string query=Uri.UnescapeDataString(handler.Requests[0]);Assert.Contains(SoftwareEvidence.Cpe,query);Assert.DoesNotContain("fixture.exe",query);Assert.DoesNotContain("Vendor",query);
    }
    [Theory][InlineData("cursor")][InlineData("oversize")][InlineData("failure")]
    public async Task NvdRejectsUnexpectedPagesOversizedResponsesAndProviderFailures(string scenario)
    {
        var handler=new FixtureHandler(_=>scenario=="failure"?new(HttpStatusCode.ServiceUnavailable):new(HttpStatusCode.OK){Content=new StringContent(scenario=="oversize"?new string('x',4*1024*1024+1):"{\"startIndex\":200,\"totalResults\":0,\"vulnerabilities\":[]}")});
        using var client=new NvdClient(handler,new("http://127.0.0.1/"),allowLoopbackFixture:true);
        if(scenario=="failure")await Assert.ThrowsAsync<HttpRequestException>(()=>client.FetchPageAsync(SoftwareEvidence.Mapping(),0,200));
        else await Assert.ThrowsAsync<InvalidDataException>(()=>client.FetchPageAsync(SoftwareEvidence.Mapping(),0,200));
    }
    [Fact]
    public async Task SoftwareEndpointsRequireEnrollmentAndOperatorAccessAndMappingReviewsRequireCsrf()
    {
        await using var operations=await OperationsFixture.CreateAsync();await using var software=await SoftwareFixture.CreateAsync();
        var parent=new ProcessParent(10,Guid.NewGuid(),DateTimeOffset.UtcNow.AddMinutes(-1),ProcessName:"php-cgi",ExecutablePath:@"C:\php\php-cgi.exe");
        var observed=SoftwareFixture.Record(source:InventorySource.RunningProcess,artifact:new("cmd.exe",Publisher:"Vendor",Product:"Widget",ProductVersion:"1.2.0",
            ProcessId:20,ProcessInstanceId:Guid.NewGuid(),ReportedRunning:true,ParentProcessId:parent.ProcessId,ParentProcess:parent));
        await software.Inventory.ApplyAsync(await software.AppendAsync(observed),DateTimeOffset.UtcNow);
        await using var exposures=SqliteExposureStore.Open(software.PathFor("exposure.db"));
        await using var host=await DashboardTestHost.StartAsync(operations,configure:services=>
        {
            services.AddSingleton(new ServerInventory([new(software.Node,software.LedgerId,"Inventory fixture")]));
            services.AddSingleton<IInventoryReader>(software.Inventory);services.AddSingleton<IExposureReader>(exposures);services.AddSingleton<IMappingReviewer>(exposures);services.AddSingleton<ICveEvidenceReader>(exposures);services.AddSingleton<ISoftwareMonitor>(new FixtureMonitor());
        });
        using var client=host.Client();string scope=DashboardTestHost.Scope(software.Node,software.LedgerId);
        Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/dashboard/api/software?"+scope)).StatusCode);
        await DashboardTestHost.LoginAsync(client);using var page=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/software?"+scope));
        Assert.Equal(1,page.RootElement.GetProperty("items").GetArrayLength());Assert.True(page.RootElement.GetProperty("status").GetProperty("enabled").GetBoolean());
        var retainedParent=page.RootElement.GetProperty("items")[0].GetProperty("observation").GetProperty("artifact").GetProperty("parentProcess");
        Assert.Equal(parent.ProcessInstanceId,retainedParent.GetProperty("processInstanceId").GetGuid());
        Assert.Equal(parent.ExecutablePath,retainedParent.GetProperty("executablePath").GetString());
        Assert.Equal(HttpStatusCode.NotFound,(await client.GetAsync("/dashboard/api/software?nodeId=not-enrolled&ledgerId="+software.LedgerId)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,(await client.GetAsync("/dashboard/api/software?"+scope+"&limit=101")).StatusCode);
        object review=new{id="widget",revision=1,publisher="Vendor",product="Widget",cpe=SoftwareEvidence.Cpe,scheme="Numeric",versionField="ProductVersion"};
        Assert.Equal(HttpStatusCode.BadRequest,(await client.PostAsJsonAsync("/dashboard/api/mappings",review)).StatusCode);
        using var session=JsonDocument.Parse(await client.GetStringAsync("/dashboard/api/session"));string csrf=session.RootElement.GetProperty("csrfToken").GetString()!;
        using var request=new HttpRequestMessage(HttpMethod.Post,"/dashboard/api/mappings"){Content=JsonContent.Create(review)};request.Headers.Add("X-CSRF-TOKEN",csrf);
        using var response=await client.SendAsync(request);response.EnsureSuccessStatusCode();var mapping=Assert.Single(await exposures.ReadMappingsAsync());Assert.Equal("operator",mapping.Reviewer);
        Assert.Single((await client.GetFromJsonAsync<ProductMapping[]>("/dashboard/api/mappings",InventoryJson.Options))!);
        await exposures.StorePageAsync(mapping,0,[SoftwareEvidence.Cve()],1,DateTimeOffset.UtcNow,TimeSpan.FromHours(6));
        var source=await client.GetFromJsonAsync<CveEvidence>("/dashboard/api/intelligence/widget/CVE-2026-12345",InventoryJson.Options);Assert.NotNull(source);Assert.NotEmpty(source.Record.Configurations);
        Assert.Single(await exposures.ReadMappingHistoryAsync(mapping.Id));Assert.Contains("software-items-tab",await client.GetStringAsync("/dashboard"));
    }
    private sealed class FixtureHandler(Func<HttpRequestMessage,HttpResponseMessage> send):HttpMessageHandler
    {public List<string> Requests{get;}=[];protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct){Requests.Add(request.RequestUri!.AbsoluteUri);return Task.FromResult(send(request));}}
    private sealed class FixtureMonitor:ISoftwareMonitor{public SoftwareStatus Status=>new(true,DateTimeOffset.UtcNow,DateTimeOffset.UtcNow,null,false);}
}
