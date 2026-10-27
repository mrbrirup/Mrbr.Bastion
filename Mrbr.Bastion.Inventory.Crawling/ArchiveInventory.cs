using System.Buffers.Binary;
using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Mrbr.Bastion.Inventory.Contracts;

namespace Mrbr.Bastion.Inventory.Crawling;

public sealed record ArchiveObservation(SoftwareArtifact? Artifact,InventoryCoverage? Issue);
public sealed class ArchiveInventory(IArtifactInspector inspector,CrawlerTask limits)
{
    private int _entries;private long _expanded;
    public static bool IsArchive(string path)=>new[]{".zip",".jar",".tar",".gz"}.Contains(Path.GetExtension(path),StringComparer.OrdinalIgnoreCase);
    public async IAsyncEnumerable<ArchiveObservation> ReadAsync(string path,[EnumeratorCancellation]CancellationToken ct=default)
    {
        var length=new FileInfo(path).Length;if(length>64*1024*1024){yield return new(null,new("ArchiveInputBudgetExceeded",path));yield break;}
        using var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete,32768,true);
        using var bounded=new MemoryStream();byte[] buffer=new byte[32768];int read;
        while((read=await input.ReadAsync(buffer,ct))>0){if(bounded.Length+read>64*1024*1024)throw new InvalidDataException("Archive input changed beyond its limit.");bounded.Write(buffer,0,read);}
        byte[] bytes=bounded.ToArray();
        if(bytes.LongLength!=length)throw new InvalidDataException("Archive input changed during inspection.");
        await foreach(var item in ReadContainer(path,"",path,bytes,0,ct))yield return item;
    }
    private async IAsyncEnumerable<ArchiveObservation> ReadContainer(string outer,string prefix,string name,byte[] bytes,int depth,[EnumeratorCancellation]CancellationToken ct)
    {
        if(depth>limits.MaximumArchiveDepth){yield return new(null,new("ArchiveDepthBudgetExceeded",InventoryJson.BoundedLocation(outer+"!"+prefix)));yield break;}
        var outputs=new List<ArchiveObservation>();
        try
        {
            string extension=Path.GetExtension(name).ToLowerInvariant();
            if(extension is ".zip" or ".jar")
            {
                PreflightZip(bytes);using var zip=new ZipArchive(new MemoryStream(bytes),ZipArchiveMode.Read,false);
                foreach(var entry in zip.Entries)
                {
                    ct.ThrowIfCancellationRequested();CountEntry();if(entry.FullName.EndsWith('/'))continue;
                    string member=prefix+entry.FullName;ValidateMember(member);
                    if(((entry.ExternalAttributes>>16)&0xf000)==0xa000){outputs.Add(new(null,new("ArchiveLinkSkipped",outer+"!"+member)));continue;}
                    if(!Wanted(entry.FullName))continue;
                    if(entry.Length>limits.MaximumEntryBytes || entry.Length/Math.Max(1,entry.CompressedLength)>limits.MaximumCompressionRatio)throw new InvalidDataException("ArchiveExpansionBudgetExceeded");
                    using var input=entry.Open();byte[] content=await ReadBounded(input,ct);
                    outputs.AddRange(await InspectMember(outer,member,entry.FullName,content,depth,ct));
                }
            }
            else if(extension==".tar")
            {
                using var tar=new TarReader(new MemoryStream(bytes));TarEntry? entry;
                while((entry=await tar.GetNextEntryAsync(false,ct))is not null)
                {
                    CountEntry();string member=prefix+entry.Name;ValidateMember(member);
                    if(entry.EntryType is TarEntryType.Directory)continue;
                    if(entry.EntryType is not(TarEntryType.RegularFile or TarEntryType.V7RegularFile)){outputs.Add(new(null,new("ArchiveEntryUnsupported",outer+"!"+member)));continue;}
                    if(!Wanted(entry.Name)||entry.DataStream is null)continue;
                    if(entry.Length>limits.MaximumEntryBytes)throw new InvalidDataException("ArchiveEntryBudgetExceeded");
                    outputs.AddRange(await InspectMember(outer,member,entry.Name,await ReadBounded(entry.DataStream,ct),depth,ct));
                }
            }
            else if(extension==".gz")
            {
                CountEntry();using var gzip=new GZipStream(new MemoryStream(bytes),CompressionMode.Decompress);byte[] content=await ReadBounded(gzip,ct);
                if(content.Length/Math.Max(1,bytes.Length)>limits.MaximumCompressionRatio)throw new InvalidDataException("ArchiveExpansionBudgetExceeded");
                string child=Path.GetFileNameWithoutExtension(name);outputs.AddRange(await InspectMember(outer,prefix+child,child,content,depth,ct));
            }
        }
        catch(OperationCanceledException){throw;}
        catch(Exception e)when(e is InvalidDataException or IOException or NotSupportedException or ArgumentException)
        {outputs.Add(new(null,new(e.Message is "ArchiveExpansionBudgetExceeded" or "ArchiveEntryBudgetExceeded" or "ArchiveEntriesBudgetExceeded" or "UnsafeArchiveMember" or "Zip64Unsupported"?e.Message:"ArchiveUnreadableOrUnsupported",InventoryJson.BoundedLocation(outer+"!"+prefix))));}
        foreach(var row in outputs)yield return row;
    }
    private bool Wanted(string name)=>IsArchive(name)||limits.Extensions.Contains(Path.GetExtension(name),StringComparer.OrdinalIgnoreCase)
        ||name.EndsWith("pom.properties",StringComparison.OrdinalIgnoreCase)||name.EndsWith("MANIFEST.MF",StringComparison.OrdinalIgnoreCase);
    private async Task<List<ArchiveObservation>> InspectMember(string outer,string member,string name,byte[] content,int depth,CancellationToken ct)
    {
        var rows=new List<ArchiveObservation>();
        if(IsArchive(name)){await foreach(var row in ReadContainer(outer,member+"!",name,content,depth+1,ct))rows.Add(row);}
        else if(name.EndsWith("pom.properties",StringComparison.OrdinalIgnoreCase)||name.EndsWith("MANIFEST.MF",StringComparison.OrdinalIgnoreCase))
        {
            var properties=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            foreach(var line in Encoding.UTF8.GetString(content).Split('\n')){int split=line.IndexOfAny(['=',':']);if(split>0&&line.Length<=1024)properties.TryAdd(line[..split].Trim(),line[(split+1)..].Trim());}
            string? Get(string a,string b)=>properties.GetValueOrDefault(a)??properties.GetValueOrDefault(b);
            string? publisher=Get("groupId","Implementation-Vendor"),product=Get("artifactId","Implementation-Title"),version=Get("version","Implementation-Version");
            if(new[]{publisher,product,version}.Any(v=>v?.Length>512))rows.Add(new(null,new("ArchiveMetadataBudgetExceeded",InventoryJson.BoundedLocation(outer+"!"+member))));
            else rows.Add(new(new(outer,member,publisher,product,PackageVersion:version,Sha256:Convert.ToHexString(SHA256.HashData(content)),MetadataUtc:DateTimeOffset.UtcNow),null));
        }
        else rows.Add(new(inspector.InspectBytes(outer,member,content),null));
        return rows;
    }
    private async Task<byte[]> ReadBounded(Stream input,CancellationToken ct)
    {
        using var output=new MemoryStream();byte[] buffer=new byte[32768];int size;
        while((size=await input.ReadAsync(buffer,ct))>0){_expanded+=size;if(output.Length+size>limits.MaximumEntryBytes||_expanded>limits.MaximumExpandedBytes)throw new InvalidDataException("ArchiveExpansionBudgetExceeded");output.Write(buffer,0,size);}return output.ToArray();
    }
    private void CountEntry(){if(++_entries>limits.MaximumArchiveEntries)throw new InvalidDataException("ArchiveEntriesBudgetExceeded");}
    private static void ValidateMember(string name)
    {if(name.Length>2048||name.Contains('\0')||name.Contains(':')||name.StartsWith('/')||name.StartsWith('\\')||name.Replace('\\','/').Split('/').Any(p=>p is "." or ".."))throw new InvalidDataException("UnsafeArchiveMember");}
    private void PreflightZip(byte[] bytes)
    {
        int end=-1;for(int i=bytes.Length-22;i>=Math.Max(0,bytes.Length-65557);i--)if(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i))==0x06054b50){end=i;break;}
        if(end<0)throw new InvalidDataException("ZIP directory missing.");
        int count=BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(end+10));uint start=BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(end+16));uint length=BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(end+12));
        if(count==65535||start==uint.MaxValue||length==uint.MaxValue)throw new InvalidDataException("Zip64Unsupported");
        if(count>limits.MaximumArchiveEntries||start+ (long)length>end)throw new InvalidDataException("ArchiveEntriesBudgetExceeded");
        long p=start,last=start+(long)length;int actual=0;
        while(p<last){if(++actual>limits.MaximumArchiveEntries||p+46>last||BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)p))!=0x02014b50)throw new InvalidDataException("ArchiveEntriesBudgetExceeded");
            p+=46+BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan((int)p+28))+BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan((int)p+30))+BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan((int)p+32));}
        if(p!=last||actual!=count)throw new InvalidDataException("ZIP directory count mismatch.");
    }
}
