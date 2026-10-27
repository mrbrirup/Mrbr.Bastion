using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Inventory.Contracts;

public enum InventorySource { RunningProcess, InstalledApplication, FileSystem, Archive }
public enum InventoryRecordKind { ScanStarted, Software, Coverage, ScanCompleted, ProcessStopped, ScanProgress }
public sealed record SoftwareArtifact(string Location, string? MemberPath = null, string? Publisher = null, string? Product = null,
    string? ProductVersion = null, string? FileVersion = null, string? PackageVersion = null, string? Sha256 = null,
    string? Architecture = null, int? ProcessId = null, DateTimeOffset? ProcessStartedUtc = null, Guid? ProcessInstanceId = null,
    bool ReportedRunning = false, string[]? EnvironmentCpes = null, DateTimeOffset? MetadataUtc = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? ParentProcessId = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProcessParent? ParentProcess = null);
public sealed record InventoryCoverage(string Code, string Location);
public sealed record InventoryProgress(long Pending,long Completed);
public sealed record InventoryRecord(int Version, Guid Id, Guid ScanId, string TaskId, InventorySource Source,
    InventoryRecordKind Kind, DateTimeOffset ObservedUtc, string Scope, SoftwareArtifact? Artifact = null,
    InventoryCoverage? Coverage = null, bool Complete = false,InventoryProgress? Progress=null);
public sealed record InventoryItem(long Sequence, string NodeId, Guid LedgerId, string Key, InventoryRecord Observation,
    DateTimeOffset ReceivedUtc, bool Missing = false,DateTimeOffset? MissingConfirmedUtc=null);
public sealed record InventoryScan(string NodeId, Guid LedgerId, Guid ScanId, string TaskId, InventorySource Source,
    string Scope, DateTimeOffset ReceivedUtc, bool Finished, bool Complete, int SoftwareCount, int CoverageCount,long Pending=0,long Completed=0);
public sealed record InventoryPage(InventoryItem[] Items, long? NextAfter);
public interface IInventoryReader
{
    Task<InventoryPage> ReadAsync(string nodeId, Guid ledgerId, long after = 0, int limit = 100, string? search = null, CancellationToken cancellationToken = default);
    Task<InventoryScan[]> ReadScansAsync(string nodeId, Guid ledgerId, CancellationToken cancellationToken = default);
    Task<InventoryRecord[]> ReadCoverageAsync(string nodeId,Guid ledgerId,Guid? scanId=null,CancellationToken cancellationToken=default);
}
public interface IArtifactInspector
{
    Task<SoftwareArtifact> InspectAsync(string path, CancellationToken cancellationToken = default);
    SoftwareArtifact InspectBytes(string location, string member, ReadOnlyMemory<byte> data);
}
public static class InventoryJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, PropertyNameCaseInsensitive = false, MaxDepth = 24, Converters = { new JsonStringEnumConverter(allowIntegerValues:false) } };
    public const int MaximumRecordBytes = 32768;
    public static byte[] Encode(InventoryRecord[] records)
    {
        if(records.Length is < 1 or > 100) throw new InvalidDataException("Inventory batches require 1 to 100 records.");
        foreach(var r in records) Validate(r);
        var bytes=JsonSerializer.SerializeToUtf8Bytes(records,Options);
        if(bytes.Length>4*1024*1024) throw new InvalidDataException("Inventory payload exceeds its limit."); return bytes;
    }
    public static InventoryRecord[] Decode(ReadOnlySpan<byte> payload)
    {
        if(payload.Length is < 1 or > 4*1024*1024) throw new InvalidDataException("Invalid inventory payload size.");
        try { var rows=JsonSerializer.Deserialize<InventoryRecord[]>(payload,Options) ?? throw new InvalidDataException("Missing inventory records.");
            if(rows.Length is < 1 or > 100) throw new InvalidDataException("Invalid inventory record count."); foreach(var r in rows) Validate(r); return rows; }
        catch(JsonException e) {throw new InvalidDataException("Malformed inventory payload.",e);}
    }
    public static string Hash(params string?[] values)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(values)));
    public static string BoundedLocation(string value)=>value.Length<=4096?value:value[..4000]+"…#"+Hash(value);
    public static string ItemKey(InventoryRecord r) => Hash(r.Source.ToString(),r.TaskId,r.Scope,r.Artifact?.ProcessInstanceId is null?r.Artifact?.Location:null,r.Artifact?.MemberPath,
        r.Artifact?.ProcessId?.ToString(System.Globalization.CultureInfo.InvariantCulture), r.Artifact?.ProcessInstanceId is null?r.Artifact?.ProcessStartedUtc?.ToString("O"):null, r.Artifact?.ProcessInstanceId?.ToString("D"));
    private static void Text(string? value,int limit,bool required=false)
    {
        if((required&&string.IsNullOrWhiteSpace(value)) || value?.Length>limit) throw new InvalidDataException("Invalid inventory text.");
        try { if(value is not null) _=new UTF8Encoding(false,true).GetByteCount(value); } catch(EncoderFallbackException e){throw new InvalidDataException("Invalid inventory Unicode.",e);}
    }
    public static void Validate(InventoryRecord r)
    {
        if(r is null || r.Version!=1 || r.Id==Guid.Empty || r.ScanId==Guid.Empty || !Enum.IsDefined(r.Source)||!Enum.IsDefined(r.Kind)
            || r.ObservedUtc==default || r.ObservedUtc.Offset!=TimeSpan.Zero) throw new InvalidDataException("Invalid inventory identity.");
        Text(r.TaskId,128,true); Text(r.Scope,4096,true);
        if(r.Kind is InventoryRecordKind.Software or InventoryRecordKind.ProcessStopped)
        {
            if(r.Artifact is not {} a || r.Coverage is not null) throw new InvalidDataException("Missing software observation.");
            Text(a.Location,4096,true);Text(a.MemberPath,4096); Text(a.Publisher,512);Text(a.Product,512);Text(a.ProductVersion,512);Text(a.FileVersion,512);Text(a.PackageVersion,512);Text(a.Architecture,64);
            if(a.Sha256 is {} h && (h.Length!=64||h.Any(c=>!char.IsAsciiHexDigitUpper(c)))) throw new InvalidDataException("Invalid artifact hash.");
            if(a.ProcessId is < 0 || a.ProcessStartedUtc is {} t && t.Offset!=TimeSpan.Zero || a.ProcessInstanceId==Guid.Empty
                || a.MetadataUtc is {} mt && mt.Offset!=TimeSpan.Zero
                || a.ReportedRunning && (r.Source!=InventorySource.RunningProcess || a.ProcessId is null || a.MemberPath is not null || a.ProcessStartedUtc is null&&a.ProcessInstanceId is null)
                || r.Kind==InventoryRecordKind.ProcessStopped&&(r.Source!=InventorySource.RunningProcess||a.ReportedRunning||a.ProcessId is null||a.ProcessStartedUtc is null&&a.ProcessInstanceId is null)) throw new InvalidDataException("Invalid process observation.");
            if(a.ParentProcessId is <0 || (a.ParentProcessId is not null || a.ParentProcess is not null)
                && (r.Source!=InventorySource.RunningProcess || a.ProcessId is null)) throw new InvalidDataException("Invalid parent process observation.");
            if(a.ParentProcess is {} parent)
            {
                parent.Validate(a.ProcessId!.Value,a.ProcessInstanceId,r.ObservedUtc);
                if(a.ParentProcessId!=parent.ProcessId || a.ProcessInstanceId is null)
                    throw new InvalidDataException("Parent context does not match the inventory process identities.");
            }
            if(a.EnvironmentCpes?.Length>32) throw new InvalidDataException("Too many environment identifiers.");
            foreach(var c in a.EnvironmentCpes??[]) Text(c,1024,true);
        }
        else if(r.Artifact is not null) throw new InvalidDataException("Unexpected software payload.");
        if(r.Kind==InventoryRecordKind.Coverage)
        {if(r.Coverage is null)throw new InvalidDataException("Missing coverage evidence.");Text(r.Coverage.Code,128,true);Text(r.Coverage.Location,4096,true);}
        else if(r.Coverage is not null)throw new InvalidDataException("Unexpected coverage evidence.");
        if(r.Complete&&r.Kind!=InventoryRecordKind.ScanCompleted)throw new InvalidDataException("Invalid completion marker.");
        if(r.Kind==InventoryRecordKind.ScanProgress?(r.Progress is null||r.Progress.Pending is <0 or >1000000||r.Progress.Completed is <0 or >1000000):r.Progress is not null)throw new InvalidDataException("Invalid crawler progress.");
        if(JsonSerializer.SerializeToUtf8Bytes(r,Options).Length>MaximumRecordBytes) throw new InvalidDataException("Inventory observation too large.");
    }
}
public sealed class InventoryPayloadCodec : IBlockPayloadCodec
{
    public string Format=>LedgerProtocol.InventoryPayloadFormat;
    public void Validate(ReadOnlyMemory<byte> payload,int recordCount)
    {if(InventoryJson.Decode(payload.Span).Length!=recordCount) throw new InvalidDataException("Inventory record count mismatch.");}
}
