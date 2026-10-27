using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Reflection.PortableExecutable;
using Mrbr.Bastion.Inventory.Contracts;

namespace Mrbr.Bastion.Inventory.Discovery;

/// <summary>Reads bytes and PE resources without loading or executing discovered code.</summary>
public sealed class ArtifactInspector(long maximumBytes=64*1024*1024) : IArtifactInspector
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string,SoftwareArtifact> _metadata=new(StringComparer.Ordinal);
    public async Task<SoftwareArtifact> InspectAsync(string path,CancellationToken cancellationToken=default)
    {
        var before=new FileInfo(path); long size=before.Length;var modified=before.LastWriteTimeUtc;
        if(size>maximumBytes)throw new InvalidDataException("FileByteBudgetExceeded");
        using var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete,65536,FileOptions.Asynchronous|FileOptions.SequentialScan);
        using var memory=new MemoryStream(); byte[] buffer=new byte[65536];int read;
        while((read=await input.ReadAsync(buffer,cancellationToken))!=0)
        {if(memory.Length+read>maximumBytes)throw new InvalidDataException("FileByteBudgetExceeded");memory.Write(buffer,0,read);}
        var after=new FileInfo(path);
        if(size!=memory.Length || after.Length!=size || after.LastWriteTimeUtc!=modified)throw new IOException("FileChangedDuringRead");
        return InspectBytes(Path.GetFullPath(path),null!,memory.ToArray());
    }
    public SoftwareArtifact InspectBytes(string location,string member,ReadOnlyMemory<byte> data)
    {
        if(data.Length>maximumBytes)throw new InvalidDataException("FileByteBudgetExceeded");
        var artifact=new SoftwareArtifact(location,member,Sha256:Convert.ToHexString(SHA256.HashData(data.Span)),MetadataUtc:DateTimeOffset.UtcNow);
        if(_metadata.TryGetValue(artifact.Sha256!,out var cached))return cached with{Location=location,MemberPath=member,MetadataUtc=artifact.MetadataUtc};
        if(data.Length<64 || data.Span[0]!='M'||data.Span[1]!='Z')return artifact;
        try
        {
            using var pe=new PEReader(new MemoryStream(data.ToArray(),writable:false));
            string arch=pe.PEHeaders.CoffHeader.Machine.ToString();
            var resources=pe.PEHeaders.PEHeader?.ResourceTableDirectory;
            if(resources is null || resources.Value.Size==0)return artifact with{Architecture=arch};
            var resource=pe.GetSectionData(resources.Value.RelativeVirtualAddress).GetContent(0,Math.Min(resources.Value.Size,2*1024*1024)).ToArray();
            int budget=4096;var version=FindVersion(resource,0,0,pe,ref budget);
            if(version is null)return artifact with{Architecture=arch};
            var fields=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);ParseVersion(version,0,version.Length,0,fields);
            string? Get(string key)=>fields.GetValueOrDefault(key) is {} v && v.Length<=512 ? v.TrimEnd('\0') : null;
            var result=artifact with {Architecture=arch,Publisher=Get("CompanyName"),Product=Get("ProductName"),ProductVersion=Get("ProductVersion"),FileVersion=Get("FileVersion")};
            if(_metadata.Count>=256)_metadata.Clear();_metadata.TryAdd(artifact.Sha256!,result with{Location="",MemberPath=null,MetadataUtc=null});return result;
        }
        catch(Exception e) when(e is BadImageFormatException or ArgumentOutOfRangeException or InvalidOperationException or IOException or OverflowException){return artifact;}
    }
    private static byte[]? FindVersion(byte[] bytes,int offset,int depth,PEReader pe,ref int budget)
    {
        if(depth>3 || offset<0 || offset+16>bytes.Length)return null;
        int count=BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset+12))+BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset+14));
        if(count>4096 || offset+16+8L*count>bytes.Length)return null;
        for(int i=0;i<count;i++)
        {
            if(--budget<0)break;
            int p=offset+16+i*8;uint name=BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(p));uint target=BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(p+4));
            if(depth==0&&name!=16)continue;
            if((target&0x80000000)!=0){var found=FindVersion(bytes,(int)(target&0x7fffffff),depth+1,pe,ref budget);if(found is not null)return found;}
            else if(target+16<=bytes.Length)
            {int rva=BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan((int)target));int size=BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan((int)target+4));
                if(size is > 0 and <= 1048576)return pe.GetSectionData(rva).GetContent(0,size).ToArray();}
        }
        return null;
    }
    private static void ParseVersion(byte[] data,int start,int end,int depth,Dictionary<string,string> values)
    {
        if(depth>8 || start+6>end)return;
        int length=BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(start));int valueLength=BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(start+2));
        int type=BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(start+4));if(length<6 || start+length>end)return;
        end=start+length;int p=start+6,keyStart=p;while(p+1<end&&(data[p]!=0||data[p+1]!=0))p+=2;if(p+1>=end)return;
        string key=System.Text.Encoding.Unicode.GetString(data,keyStart,p-keyStart);p=(p+2+3)&~3;
        int valueBytes=type==1?valueLength*2:valueLength;
        if(p+valueBytes>end)return;
        if(type==1 && valueBytes>0 && key.Length<=128)values.TryAdd(key,System.Text.Encoding.Unicode.GetString(data,p,valueBytes));
        p=(p+valueBytes+3)&~3;
        while(p+6<=end){int child=BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(p));if(child<6||p+child>end)break;ParseVersion(data,p,p+child,depth+1,values);p=(p+child+3)&~3;}
    }
}
