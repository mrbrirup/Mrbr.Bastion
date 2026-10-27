using System.Net;
using System.Text.Json;

namespace Mrbr.Bastion.Vulnerabilities.Nvd;

/// <summary>Central-only NVD 2.0 adapter. It sends reviewed CPE names or explicit operator search terms.</summary>
public sealed class NvdClient : IVulnerabilityProvider,IDisposable
{
    private readonly HttpClient _http;private readonly SemaphoreSlim _gate=new(1,1);private readonly string? _key;
    private DateTimeOffset _next;private readonly TimeSpan _interval;private readonly Uri _root;
    public NvdClient(string? apiKey=null):this(new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=false,AutomaticDecompression=DecompressionMethods.None},new("https://services.nvd.nist.gov/"),apiKey){ }
    public NvdClient(HttpMessageHandler handler,Uri root,string? apiKey=null,bool allowLoopbackFixture=false)
    {
        if(root.Scheme!="https"&&!(allowLoopbackFixture&&root.IsLoopback&&IPAddress.TryParse(root.Host,out var ip)&&IPAddress.IsLoopback(ip)))throw new ArgumentException("NVD requires HTTPS.");
        if(root.UserInfo.Length>0||root.Query.Length>0||root.Fragment.Length>0)throw new ArgumentException("Invalid NVD endpoint.");
        _root=root;_key=apiKey;_interval=allowLoopbackFixture?TimeSpan.Zero:TimeSpan.FromMilliseconds(string.IsNullOrEmpty(apiKey)?6100:700);
        _http=new(handler,true){Timeout=TimeSpan.FromSeconds(45)};
    }
    public async Task<(CveRecord[] Records,int Total)> FetchPageAsync(ProductMapping mapping,int startIndex,int pageSize,CancellationToken cancellationToken=default)
    {
        MappingValidation.Validate(mapping);if(startIndex<0||pageSize is <1 or >200)throw new ArgumentException("Invalid NVD page.");
        using var document=await GetAsync($"rest/json/cves/2.0?virtualMatchString={Uri.EscapeDataString(mapping.Cpe)}&startIndex={startIndex}&resultsPerPage={pageSize}",cancellationToken);
        var root=document.RootElement;
        if(root.GetProperty("startIndex").GetInt32()!=startIndex)throw new InvalidDataException("NVD page cursor mismatch.");
        int total=root.GetProperty("totalResults").GetInt32();var values=root.GetProperty("vulnerabilities");
        if(total<0||total>20000||values.GetArrayLength()>pageSize)throw new InvalidDataException("NVD query capacity exceeded.");
        return(values.EnumerateArray().Select(v=>Parse(v.GetProperty("cve"))).ToArray(),total);
    }
    public async Task<string[]> SearchProductsAsync(string query,CancellationToken cancellationToken=default)
    {
        if(string.IsNullOrWhiteSpace(query)||query.Length>128||query.Any(char.IsControl))throw new ArgumentException("Invalid product query.");
        using var d=await GetAsync("rest/json/cpes/2.0?resultsPerPage=20&keywordSearch="+Uri.EscapeDataString(query),cancellationToken);
        return d.RootElement.GetProperty("products").EnumerateArray().Take(20).Select(p=>p.GetProperty("cpe").GetProperty("cpeName").GetString()??"").Where(p=>p.Length<=1024).ToArray();
    }
    private async Task<JsonDocument> GetAsync(string relative,CancellationToken ct)
    {
        await _gate.WaitAsync(ct);try
        {
            var delay=_next-DateTimeOffset.UtcNow;if(delay>TimeSpan.Zero)await Task.Delay(delay,ct);
            _next=DateTimeOffset.UtcNow+_interval;
            using var request=new HttpRequestMessage(HttpMethod.Get,new Uri(_root,relative));request.Headers.UserAgent.ParseAdd("Mrbr.Bastion/1.0");if(!string.IsNullOrEmpty(_key))request.Headers.Add("apiKey",_key);
            using var response=await _http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,ct);
            if(response.StatusCode==(HttpStatusCode)429||response.StatusCode==HttpStatusCode.ServiceUnavailable)
            {
                TimeSpan retry=response.Headers.RetryAfter?.Delta??(response.Headers.RetryAfter?.Date-DateTimeOffset.UtcNow)??TimeSpan.FromMinutes(1);
                _next=DateTimeOffset.UtcNow+TimeSpan.FromSeconds(Math.Clamp(retry.TotalSeconds,1,3600));
            }
            if(!response.IsSuccessStatusCode)throw new HttpRequestException("NVD request failed.",null,response.StatusCode);
            if(response.Content.Headers.ContentLength>4*1024*1024)throw new InvalidDataException("NVD response budget exceeded.");
            using var stream=await response.Content.ReadAsStreamAsync(ct);using var body=new MemoryStream();var buffer=new byte[32768];int n;
            while((n=await stream.ReadAsync(buffer,ct))>0){if(body.Length+n>4*1024*1024)throw new InvalidDataException("NVD response budget exceeded.");body.Write(buffer,0,n);}
            return JsonDocument.Parse(body.ToArray(),new(){MaxDepth=64});
        }finally{_gate.Release();}
    }
    public static CveRecord Parse(JsonElement cve)
    {
        string id=Text(cve,"id",32)??throw new InvalidDataException("CVE identity missing.");
        if(!System.Text.RegularExpressions.Regex.IsMatch(id,@"^CVE-[0-9]{4}-[0-9]{4,19}$",System.Text.RegularExpressions.RegexOptions.CultureInvariant))throw new InvalidDataException("Invalid CVE identity.");
        var configurations=new List<ApplicabilityNode>();
        if(cve.TryGetProperty("configurations",out var configs))foreach(var config in configs.EnumerateArray()){if(configurations.Count>=256)throw new InvalidDataException("CVE applicability budget exceeded.");configurations.Add(Node(config,0));}
        double? score=null;
        if(cve.TryGetProperty("metrics",out var metrics))foreach(var key in new[]{"cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"})
            if(metrics.TryGetProperty(key,out var group)&&group.GetArrayLength()>0&&group[0].TryGetProperty("cvssData",out var cvss)&&cvss.TryGetProperty("baseScore",out var value)){double s=value.GetDouble();if(s is >=0 and <=10)score=s;break;}
        string description="";if(cve.TryGetProperty("descriptions",out var descriptions))foreach(var d in descriptions.EnumerateArray())if(Text(d,"lang",16)=="en"){description=Text(d,"value",16000)??"";break;}
        DateTimeOffset modified=DateTimeOffset.Parse(cve.GetProperty("lastModified").GetString()!,System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.AssumeUniversal).ToUniversalTime();
        var tags=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if(cve.TryGetProperty("cveTags",out var tagGroups))foreach(var group in tagGroups.EnumerateArray())if(group.TryGetProperty("tags",out var values))foreach(var tag in values.EnumerateArray())
        {string? value=tag.GetString();if(value?.Length>64||tags.Count>=32)throw new InvalidDataException("CVE tag budget exceeded.");if(value is not null)tags.Add(value);}
        return new(id,Text(cve,"vulnStatus",64)??"Unknown",description,"https://nvd.nist.gov/vuln/detail/"+id,modified,score,configurations.ToArray(),tags.ToArray());
    }
    private static ApplicabilityNode Node(JsonElement e,int depth)
    {
        if(depth>16)throw new InvalidDataException("CVE applicability depth exceeded.");
        var matches=new List<CpeCriterion>();var children=new List<ApplicabilityNode>();
        if(e.TryGetProperty("cpeMatch",out var list))foreach(var m in list.EnumerateArray()){if(matches.Count>=256)throw new InvalidDataException("CVE match budget exceeded.");matches.Add(new(Text(m,"criteria",1024)??"",m.TryGetProperty("vulnerable",out var v)&&v.GetBoolean(),Text(m,"versionStartIncluding",512),Text(m,"versionStartExcluding",512),Text(m,"versionEndIncluding",512),Text(m,"versionEndExcluding",512)));}
        foreach(var key in new[]{"nodes","children"})if(e.TryGetProperty(key,out var nodes))foreach(var n in nodes.EnumerateArray()){if(children.Count>=256)throw new InvalidDataException("CVE node budget exceeded.");children.Add(Node(n,depth+1));}
        // NVD configurations wrap nodes with an implicit OR when no operator is present.
        return new(Text(e,"operator",8)??"OR",e.TryGetProperty("negate",out var negate)&&negate.GetBoolean(),matches.ToArray(),children.ToArray());
    }
    private static string? Text(JsonElement e,string name,int max){if(!e.TryGetProperty(name,out var p)||p.ValueKind==JsonValueKind.Null)return null;string? s=p.GetString();if(s?.Length>max)throw new InvalidDataException("NVD field budget exceeded.");return s;}
    public void Dispose(){_http.Dispose();_gate.Dispose();}
}
