using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

namespace Mrbr.Bastion.Vulnerabilities;

public sealed record CpeName(string[] Parts)
{
    public static CpeName Parse(string value)
    {
        if(value is null||value.Length>1024||!value.StartsWith("cpe:2.3:",StringComparison.Ordinal))throw new ArgumentException("A complete CPE 2.3 name is required.");
        var parts=new List<string>();var text=new StringBuilder();bool escape=false;
        foreach(char c in value[8..]){if(escape){text.Append('\\').Append(c);escape=false;}else if(c=='\\')escape=true;else if(c==':'){parts.Add(text.ToString());text.Clear();}else text.Append(c);}
        if(escape)throw new ArgumentException("Invalid CPE escape.");parts.Add(text.ToString());
        if(parts.Count!=11||parts.Any(p=>p.Length==0||p.Any(char.IsControl)))throw new ArgumentException("Invalid CPE components.");return new(parts.ToArray());
    }
    public bool SameProduct(CpeName other)=>Parts.Take(3).SequenceEqual(other.Parts.Take(3),StringComparer.OrdinalIgnoreCase);
}
public static partial class VersionOrdering
{
    [GeneratedRegex(@"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",RegexOptions.CultureInvariant|RegexOptions.NonBacktracking)]
    private static partial Regex SemverPattern();
    public static int? Compare(string a,string b,VersionScheme scheme)
    {
        if(a.Length>512||b.Length>512)return null;
        if(scheme==VersionScheme.Exact)return a==b?0:null;
        if(scheme==VersionScheme.Numeric)
        {
            var x=a.Split('.');var y=b.Split('.');if(x.Length>16||y.Length>16||x.Concat(y).Any(p=>p.Length==0||p.Any(c=>!char.IsAsciiDigit(c))))return null;
            for(int i=0;i<Math.Max(x.Length,y.Length);i++){int c=(i<x.Length?BigInteger.Parse(x[i],System.Globalization.CultureInfo.InvariantCulture):BigInteger.Zero).CompareTo(i<y.Length?BigInteger.Parse(y[i],System.Globalization.CultureInfo.InvariantCulture):BigInteger.Zero);if(c!=0)return Math.Sign(c);}return 0;
        }
        var left=SemverPattern().Match(a);var right=SemverPattern().Match(b);if(!left.Success||!right.Success)return null;
        string[] lp=left.Groups[4].Success?left.Groups[4].Value.Split('.'):[],rp=right.Groups[4].Success?right.Groups[4].Value.Split('.'):[];
        if(lp.Concat(rp).Any(p=>p.All(char.IsAsciiDigit)&&p.Length>1&&p[0]=='0'))return null;
        for(int i=1;i<=3;i++){int c=BigInteger.Parse(left.Groups[i].Value,System.Globalization.CultureInfo.InvariantCulture).CompareTo(BigInteger.Parse(right.Groups[i].Value,System.Globalization.CultureInfo.InvariantCulture));if(c!=0)return Math.Sign(c);}
        if(lp.Length==0||rp.Length==0)return lp.Length==rp.Length?0:lp.Length==0?1:-1;
        for(int i=0;i<Math.Min(lp.Length,rp.Length);i++){bool ln=lp[i].All(char.IsAsciiDigit),rn=rp[i].All(char.IsAsciiDigit);int c=ln&&rn?BigInteger.Parse(lp[i],System.Globalization.CultureInfo.InvariantCulture).CompareTo(BigInteger.Parse(rp[i],System.Globalization.CultureInfo.InvariantCulture)):ln!=rn?ln?-1:1:string.CompareOrdinal(lp[i],rp[i]);if(c!=0)return Math.Sign(c);}return Math.Sign(lp.Length.CompareTo(rp.Length));
    }
}
public static class ApplicabilityEvaluator
{
    private enum Truth{No,Yes,Unknown}
    private sealed record Result(Truth Value,bool Target,bool Potential);
    public static (Applicability State,string Reason) Evaluate(CveRecord cve,ProductMapping mapping,string? version,string[]? environments=null)
    {
        MappingValidation.Validate(mapping);
        if(cve.Status.Equals("Rejected",StringComparison.OrdinalIgnoreCase))return(Applicability.NotAffected,"SourceRejectedRecord");
        if(cve.Status.Equals("Withdrawn",StringComparison.OrdinalIgnoreCase)||cve.Tags?.Contains("disputed",StringComparer.OrdinalIgnoreCase)==true)return(Applicability.Unknown,"SourceDisputedOrWithdrawn");
        if(string.IsNullOrWhiteSpace(version))return(Applicability.Unknown,"VersionUnavailable");
        if(cve.Configurations.Length==0)return(Applicability.Unknown,"ApplicabilityUnavailable");
        var family=CpeName.Parse(mapping.Cpe);var known=new HashSet<string>(environments??[],StringComparer.OrdinalIgnoreCase);
        var results=cve.Configurations.Select(n=>Node(n,0)).ToArray();
        if(results.Any(r=>r.Value==Truth.Yes&&r.Target))return(Applicability.Affected,"PublishedCriteriaMatched");
        if(results.Any(r=>r.Value==Truth.Unknown&&r.Potential))return(Applicability.Unknown,"UnsupportedOrMissingPrerequisites");
        if(results.Any(r=>r.Potential)&&results.All(r=>r.Value==Truth.No))return(Applicability.NotAffected,"PublishedVersionCriteriaExcluded");
        return(Applicability.Unknown,"NoApplicableProductEvidence");
        Result Node(ApplicabilityNode n,int depth)
        {
            if(depth>16||n.Matches.Length+n.Children.Length>256||n.Operator is not("AND" or "OR"))return new(Truth.Unknown,false,true);
            var children=n.Matches.Select(Match).Concat(n.Children.Select(c=>Node(c,depth+1))).ToArray();
            if(children.Length==0)return new(Truth.Unknown,false,true);
            Truth value=n.Operator=="AND"?(children.Any(c=>c.Value==Truth.No)?Truth.No:children.Any(c=>c.Value==Truth.Unknown)?Truth.Unknown:Truth.Yes)
                :(children.Any(c=>c.Value==Truth.Yes)?Truth.Yes:children.Any(c=>c.Value==Truth.Unknown)?Truth.Unknown:Truth.No);
            if(n.Negate)value=value==Truth.Unknown?Truth.Unknown:value==Truth.Yes?Truth.No:Truth.Yes;
            return new(value,value==Truth.Yes&&!n.Negate&&children.Any(c=>c.Target&&c.Value==Truth.Yes),children.Any(c=>c.Potential));
        }
        Result Match(CpeCriterion c)
        {
            CpeName criterion;try{criterion=CpeName.Parse(c.Criteria);}catch(ArgumentException){return new(Truth.Unknown,false,true);}
            if(!family.SameProduct(criterion))return new(known.Contains(c.Criteria)?Truth.Yes:Truth.Unknown,false,false);
            if(c.StartIncluding is not null&&c.StartExcluding is not null||c.EndIncluding is not null&&c.EndExcluding is not null)return new(Truth.Unknown,false,c.Vulnerable);
            string? lower=c.StartIncluding??c.StartExcluding,upper=c.EndIncluding??c.EndExcluding;
            if(lower is not null&&upper is not null&&VersionOrdering.Compare(lower,upper,mapping.Scheme) is {} order
                &&(order>0||order==0&&(c.StartExcluding is not null||c.EndExcluding is not null)))return new(Truth.Unknown,false,c.Vulnerable);
            bool unknown=false;Truth truth=Truth.Yes;
            for(int i=4;i<11;i++)if(criterion.Parts[i]!="*"&&criterion.Parts[i]!=family.Parts[i])unknown=true;
            string cv=criterion.Parts[3];
            if(cv!="*"){var compared=VersionOrdering.Compare(version,cv,mapping.Scheme);if(compared is null)unknown=true;else if(compared!=0)truth=Truth.No;}
            void Boundary(string? bound,bool lower,bool inclusive){if(bound is null)return;int? cmp=VersionOrdering.Compare(version,bound,mapping.Scheme);if(cmp is null)unknown=true;else if(lower?(inclusive?cmp<0:cmp<=0):(inclusive?cmp>0:cmp>=0))truth=Truth.No;}
            Boundary(c.StartIncluding,true,true);Boundary(c.StartExcluding,true,false);Boundary(c.EndIncluding,false,true);Boundary(c.EndExcluding,false,false);
            if(truth!=Truth.No&&unknown)truth=Truth.Unknown;
            return new(truth,c.Vulnerable&&truth==Truth.Yes,c.Vulnerable);
        }
    }
}
