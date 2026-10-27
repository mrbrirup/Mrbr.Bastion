using Mrbr.Bastion.Inventory.Contracts;

namespace Mrbr.Bastion.Vulnerabilities;

/// <summary>Correlates reviewed identities. Absence, stale evidence and unsupported prerequisites remain unknown.</summary>
public sealed class ExposureCorrelator(TimeSpan observationLifetime,TimeSpan intelligenceLifetime)
{
    public ExposureFinding[] Evaluate(InventoryItem item,ProductMapping[] mappings,IntelligenceSnapshot[] intelligence,DateTimeOffset now)
    {
        var a=item.Observation.Artifact??throw new ArgumentException("A software observation is required.");
        DateTimeOffset observed=a.MetadataUtc??item.Observation.ObservedUtc;
        var candidates=mappings.Where(m=>string.Equals(m.Publisher,a.Publisher,StringComparison.OrdinalIgnoreCase)
            &&string.Equals(m.Product,a.Product,StringComparison.OrdinalIgnoreCase)).ToArray();
        ProductMapping? mapping=candidates.Length==1?candidates[0]:null;
        var snapshot=mapping is null?null:intelligence.SingleOrDefault(s=>s.MappingId==mapping.Id);
        string? version=mapping is null?null:MappingValidation.Version(a,mapping.VersionField);
        bool running=a.ReportedRunning&&!item.Missing&&now>=item.Observation.ObservedUtc&&now-item.Observation.ObservedUtc<=TimeSpan.FromMinutes(2);
        if(IsConfirmedAbsent(item,now))return snapshot?.Records.Length>0?snapshot.Records.Select(c=>Finding(c,Applicability.NotAffected,"AbsentFromCompleteScope")).ToArray():[Finding(null,Applicability.NotAffected,"AbsentFromCompleteScope")];
        string? unknown=candidates.Length==0?"NoReviewedProductMapping":candidates.Length>1?"AmbiguousProductMapping"
            :item.Missing?"ObservationNoLongerPresent":observed>now.AddMinutes(5)||item.ReceivedUtc>now.AddMinutes(5)?"ObservationClockUncertain"
            :now-observed>observationLifetime?"ObservationStale":string.IsNullOrWhiteSpace(version)?"VersionUnavailable"
            :snapshot?.FetchedUtc is null?"IntelligenceUnavailable":snapshot.Error is not null?"IntelligenceRefreshFailed"
            :!snapshot.Complete?"IntelligenceIncomplete":snapshot.FetchedUtc>now.AddMinutes(5)||now-snapshot.FetchedUtc>intelligenceLifetime?"IntelligenceStale":null;
        if(snapshot?.Records.Length is null or 0)return [Finding(null,Applicability.Unknown,unknown??"NoPublishedMatch")];
        return snapshot.Records.Select(c=>{var result=unknown is null?ApplicabilityEvaluator.Evaluate(c,mapping!,version,a.EnvironmentCpes):(Applicability.Unknown,unknown);return Finding(c,result.Item1,result.Item2);}).ToArray();
        ExposureFinding Finding(CveRecord? c,Applicability state,string reason)=>new(InventoryJson.Hash(item.NodeId,item.LedgerId.ToString("D"),item.Key,c?.Id),item.NodeId,item.LedgerId,item.Key,
            a.Location,a.MemberPath,a.Product,version,mapping?.Id,mapping?.Revision,c?.Id,state,reason,running,c?.Cvss,now,snapshot?.FetchedUtc,observed,c?.Reference,
            mapping is not null?"ReviewedExactIdentity":candidates.Length>1?"Ambiguous":"Unresolved",SourceModifiedUtc:c?.ModifiedUtc,SourceStatus:c?.Status,SourceTags:c?.Tags);
    }
    public bool IsConfirmedAbsent(InventoryItem item,DateTimeOffset now)=>item.Missing&&item.Observation.Source!=InventorySource.RunningProcess
        &&item.MissingConfirmedUtc is {} confirmed&&confirmed<=now&&now-confirmed<=observationLifetime;
}
public sealed record SoftwareStatus(bool Enabled,DateTimeOffset? LastProjectionUtc,DateTimeOffset? LastEvaluationUtc,string? Error,bool IntelligenceEnabled,string Policy="mrbr.bastion.exposure-alerts.v1");
public interface ISoftwareMonitor { SoftwareStatus Status{get;} }
public interface IMappingReviewer
{
    Task ReviewAsync(ProductMapping mapping,CancellationToken cancellationToken=default);
    Task<ProductMapping[]> ReadMappingHistoryAsync(string id,CancellationToken cancellationToken=default);
    Task<ExposureFinding[]> ReadHistoryAsync(string findingId,CancellationToken cancellationToken=default);
}
