using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Vulnerabilities;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class SoftwareCorrelationTests
{
    [Theory]
    [InlineData("1.2","1.2.0",0)]
    [InlineData("1.10","1.9",1)]
    [InlineData("9999999999999999999999999999","2",1)]
    [InlineData("1.0.0","1.0.1",-1)]
    [InlineData("1.0-vendor","1.0",null)]
    [InlineData("1..2","1.2",null)]
    public void NumericVersionsAreExplicitAndNeverLexicallyOrdered(string a,string b,int? expected)=>Assert.Equal(expected,VersionOrdering.Compare(a,b,VersionScheme.Numeric));
    [Theory]
    [InlineData("1.0.0-alpha","1.0.0",-1)]
    [InlineData("1.0.0-alpha.2","1.0.0-alpha.10",-1)]
    [InlineData("1.0.0+build1","1.0.0+build2",0)]
    [InlineData("1.0.0-1","1.0.0-alpha",-1)]
    [InlineData("1.0.0-alpha.01","1.0.0",null)]
    [InlineData("01.0.0","1.0.0",null)]
    [InlineData("1.0","1.0.0",null)]
    public void SemanticVersionsRespectPrereleasesAndRejectUnsupportedForms(string a,string b,int? expected)=>Assert.Equal(expected,VersionOrdering.Compare(a,b,VersionScheme.Semantic));
    [Theory]
    [InlineData("0.9",Applicability.NotAffected)]
    [InlineData("1.0.0",Applicability.Affected)]
    [InlineData("1.9.9",Applicability.Affected)]
    [InlineData("2.0.0",Applicability.NotAffected)]
    [InlineData("1.2-vendor-backport",Applicability.Unknown)]
    [InlineData(null,Applicability.Unknown)]
    public void PublishedBoundariesAreThreeState(string? version,Applicability expected)=>Assert.Equal(expected,ApplicabilityEvaluator.Evaluate(SoftwareEvidence.Cve(),SoftwareEvidence.Mapping(),version).State);
    [Fact]
    public void MissingEnvironmentPrerequisitesAreUnknownAndKnownPrerequisitesCanMatch()
    {
        const string os="cpe:2.3:o:vendor:os:10:*:*:*:*:*:*:*";
        var cve=SoftwareEvidence.Cve() with{Configurations=[new("AND",false,[new(os,false)],[SoftwareEvidence.Cve().Configurations[0]])]};
        Assert.Equal(Applicability.Unknown,ApplicabilityEvaluator.Evaluate(cve,SoftwareEvidence.Mapping(),"1.2.0").State);
        Assert.Equal(Applicability.Affected,ApplicabilityEvaluator.Evaluate(cve,SoftwareEvidence.Mapping(),"1.2.0",[os]).State);
    }
    [Fact]
    public void AnUnrelatedTrueBranchCannotMakeAnExcludedVulnerableBranchAffected()
    {
        var excluded=new ApplicabilityNode("AND",false,[new(SoftwareEvidence.Cpe,true),new(SoftwareEvidence.Cpe,false,StartIncluding:"5")],[]);
        var cve=SoftwareEvidence.Cve() with{Configurations=[new("OR",false,[new(SoftwareEvidence.Cpe,false)],[excluded])]};
        Assert.NotEqual(Applicability.Affected,ApplicabilityEvaluator.Evaluate(cve,SoftwareEvidence.Mapping(),"1.2").State);
    }
    [Fact]
    public void NegationAndUnsupportedOperatorsNeverInventVulnerableEvidence()
    {
        var original=SoftwareEvidence.Cve();
        Assert.NotEqual(Applicability.Affected,ApplicabilityEvaluator.Evaluate(original with{Configurations=[original.Configurations[0] with{Negate=true}]},SoftwareEvidence.Mapping(),"8").State);
        Assert.Equal(Applicability.Unknown,ApplicabilityEvaluator.Evaluate(original with{Configurations=[original.Configurations[0] with{Operator="XOR"}]},SoftwareEvidence.Mapping(),"1.2").State);
        Assert.Equal(Applicability.NotAffected,ApplicabilityEvaluator.Evaluate(original with{Status="Rejected"},SoftwareEvidence.Mapping(),"1.2").State);
    }
    [Theory]
    [InlineData("missing")][InlineData("ambiguous")][InlineData("stale-item")][InlineData("stale-source")][InlineData("failed-source")][InlineData("no-records")][InlineData("missing-item")]
    public void UncertaintyCannotBecomeAConfidentNegative(string situation)
    {
        var now=DateTimeOffset.UtcNow;var mapping=SoftwareEvidence.Mapping();var item=SoftwareEvidence.Item();ProductMapping[] maps=[mapping];
        var source=new IntelligenceSnapshot(mapping.Id,now,null,true,[SoftwareEvidence.Cve()]);
        switch(situation)
        {
            case "missing":maps=[];break;case "ambiguous":maps=[mapping,mapping with{Id="other"}];break;
            case "stale-item":item=item with{Observation=item.Observation with{ObservedUtc=now.AddDays(-2)}};break;
            case "stale-source":source=source with{FetchedUtc=now.AddDays(-2)};break;
            case "failed-source":source=source with{Error="RefreshFailed"};break;
            case "no-records":source=source with{Records=[]};break;
            case "missing-item":item=item with{Missing=true};break;
        }
        var findings=new ExposureCorrelator(TimeSpan.FromDays(1),TimeSpan.FromDays(1)).Evaluate(item,maps,[source],now);
        Assert.All(findings,f=>Assert.Equal(Applicability.Unknown,f.Applicability));
    }
    [Fact]
    public void RunningEvidenceHasAShortLifetimeAndArchivePresenceIsNotRunning()
    {
        var item=SoftwareEvidence.Item(new("fixture.exe",Publisher:"Vendor",Product:"Widget",ProductVersion:"1.2",ProcessId:7,ProcessStartedUtc:DateTimeOffset.UtcNow,ReportedRunning:true));
        item=item with{Observation=item.Observation with{Source=InventorySource.RunningProcess}};var now=DateTimeOffset.UtcNow;
        var engine=new ExposureCorrelator(TimeSpan.FromDays(1),TimeSpan.FromDays(1));var m=SoftwareEvidence.Mapping();var snapshot=new IntelligenceSnapshot(m.Id,now,null,true,[SoftwareEvidence.Cve()]);
        Assert.True(Assert.Single(engine.Evaluate(item,[m],[snapshot],now)).RecentlyRunning);
        Assert.False(Assert.Single(engine.Evaluate(item,[m],[snapshot],now.AddMinutes(3))).RecentlyRunning);
        Assert.Throws<InvalidDataException>(()=>InventoryJson.Encode([item.Observation with{Source=InventorySource.Archive}]));
    }
    [Fact]
    public void DisputedWithdrawnAndContradictorySourceCriteriaRemainUnknown()
    {
        var original=SoftwareEvidence.Cve();var mapping=SoftwareEvidence.Mapping();
        Assert.Equal(Applicability.Unknown,ApplicabilityEvaluator.Evaluate(original with{Tags=["disputed"]},mapping,"1.2").State);
        Assert.Equal(Applicability.Unknown,ApplicabilityEvaluator.Evaluate(original with{Status="Withdrawn"},mapping,"1.2").State);
        Assert.Equal(Applicability.Unknown,ApplicabilityEvaluator.Evaluate(SoftwareEvidence.Cve(start:"5",end:"2"),mapping,"1.2").State);
        Assert.Null(VersionOrdering.Compare("2.0.0-01","1.0.0",VersionScheme.Semantic));
    }
}
