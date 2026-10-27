using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Operations;
using Mrbr.Bastion.Vulnerabilities;
using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.AspNetCore;

namespace Mrbr.Bastion.Dashboard;

internal sealed record MappingReviewRequest(string Id,int Revision,string Publisher,string Product,string Cpe,VersionScheme Scheme,VersionEvidence VersionField);
internal static class SoftwareEndpoints
{
    private static readonly JsonSerializerOptions Json=new(InventoryJson.Options){MaxDepth=64};
    private static SoftwareStatus Status(HttpContext c)=>c.RequestServices.GetService<ISoftwareMonitor>()?.Status??new(false,null,null,null,false);
    private static IResult Reply<T>(T value)=>Results.Json(value,Json);
    internal static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/software",async(HttpContext c,string nodeId,Guid ledgerId,long? after,int? limit,string? search,OperationsService operations)=>
        {
            operations.RequireEnrollment(nodeId,ledgerId);var reader=c.RequestServices.GetService<IInventoryReader>();
            var page=reader is null?new InventoryPage([],null):await reader.ReadAsync(nodeId,ledgerId,after??0,limit??100,search,c.RequestAborted);
            return Reply(new{status=Status(c),page.Items,page.NextAfter});
        });
        api.MapGet("/software/scans",async(HttpContext c,string nodeId,Guid ledgerId,OperationsService operations)=>
        {operations.RequireEnrollment(nodeId,ledgerId);return Reply(c.RequestServices.GetService<IInventoryReader>() is {} reader?await reader.ReadScansAsync(nodeId,ledgerId,c.RequestAborted):Array.Empty<InventoryScan>());});
        api.MapGet("/software/coverage",async(HttpContext c,string nodeId,Guid ledgerId,Guid? scanId,OperationsService operations)=>
        {operations.RequireEnrollment(nodeId,ledgerId);return Reply(c.RequestServices.GetService<IInventoryReader>() is {} reader?await reader.ReadCoverageAsync(nodeId,ledgerId,scanId,c.RequestAborted):Array.Empty<InventoryRecord>());});
        api.MapGet("/exposures",async(HttpContext c,string nodeId,Guid ledgerId,string? after,int? limit,OperationsService operations)=>
        {operations.RequireEnrollment(nodeId,ledgerId);return Reply(c.RequestServices.GetService<IExposureReader>() is {} reader?await reader.ReadFindingsAsync(nodeId,ledgerId,after,limit??100,c.RequestAborted):new ExposurePage([],null));});
        api.MapGet("/exposures/{id}/history",async(HttpContext c,string id,OperationsService operations)=>
        {
            if(id.Length!=64||id.Any(ch=>!char.IsAsciiHexDigitUpper(ch)))return Results.BadRequest();
            var rows=c.RequestServices.GetService<IMappingReviewer>() is {} reader?await reader.ReadHistoryAsync(id,c.RequestAborted):[];
            if(rows.Length==0)return Results.NotFound();operations.RequireEnrollment(rows[0].NodeId,rows[0].LedgerId);return Reply(rows);
        }).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Evidence));
        api.MapGet("/mappings",async(HttpContext c,CancellationToken cancellationToken)=>Reply(c.RequestServices.GetService<IExposureReader>() is {} reader?await reader.ReadMappingsAsync(cancellationToken):Array.Empty<ProductMapping>()));
        api.MapGet("/mappings/{id}/history",async(HttpContext c,string id)=>Reply(c.RequestServices.GetService<IMappingReviewer>() is {} reader?await reader.ReadMappingHistoryAsync(id,c.RequestAborted):Array.Empty<ProductMapping>())).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Evidence));
        api.MapGet("/intelligence/{mappingId}/{cveId}",async(HttpContext c,string mappingId,string cveId)=>
        {var reader=c.RequestServices.GetService<ICveEvidenceReader>();var evidence=reader is null?null:await reader.ReadCveAsync(mappingId,cveId,c.RequestAborted);return evidence is null?Results.NotFound():Reply(evidence);}).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Evidence));
        api.MapPost("/mappings",async(HttpContext c,IAntiforgery csrf)=>
        {
            await csrf.ValidateRequestAsync(c);var reviewer=c.RequestServices.GetService<IMappingReviewer>();if(reviewer is null)return Results.Conflict(new{error="SoftwareInventoryDisabled"});
            if(c.Request.ContentType?.Split(';')[0].Trim()!="application/json")return Results.StatusCode(415);
            MappingReviewRequest? request;try{request=await JsonSerializer.DeserializeAsync<MappingReviewRequest>(c.Request.Body,InventoryJson.Options,c.RequestAborted);}catch(JsonException){return Results.BadRequest();}
            if(request is null)return Results.BadRequest();var mapping=new ProductMapping(request.Id,request.Revision,request.Publisher,request.Product,request.Cpe,request.Scheme,request.VersionField,OperatorAuthentication.Actor(c.User),DateTimeOffset.UtcNow);
            await reviewer.ReviewAsync(mapping,c.RequestAborted);return Reply(mapping);
        }).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Review));
        api.MapGet("/products",async(HttpContext c,string query)=>
        {var provider=c.RequestServices.GetService<IVulnerabilityProvider>();return provider is null?Results.Conflict(new{error="IntelligenceProviderDisabled"}):Reply(await provider.SearchProductsAsync(query,c.RequestAborted));}).RequireAuthorization(OperatorAuthentication.Policy(OperatorPermissions.Search));
    }
}
