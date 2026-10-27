using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Inventory.Crawling;
using Mrbr.Bastion.Inventory.Discovery;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Inventory.Windows;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class SoftwareCrawlerTests
{
    [Fact]
    public async Task CrawlerResumesItsFrontierAndOnlyCheckpointsPublishedEvidence()
    {
        using var temp=new TestLedger();string root=Path.Combine(temp.DirectoryPath,"files");Directory.CreateDirectory(Path.Combine(root,"child"));File.WriteAllText(Path.Combine(root,"child","portable.exe"),"fixture bytes");
        var task=new CrawlerTask{Id="portable",Root=root,WorkPerRound=1,DelayMilliseconds=0};string db=Path.Combine(temp.DirectoryPath,"crawler.db");var rows=new List<InventoryRecord>();
        Task Save(InventoryRecord r,CancellationToken _){rows.Add(r);return Task.CompletedTask;}
        Guid scan;
        await using(var first=SqliteCrawlerJournal.Open(db)){var state=await new InventoryCrawler(first,new ArtifactInspector()).RunRoundAsync(task,Save);scan=state.ScanId;Assert.False(state.Finished);Assert.Equal(1,state.Pending);}
        await using var resumed=SqliteCrawlerJournal.Open(db);var crawler=new InventoryCrawler(resumed,new ArtifactInspector());
        await crawler.RunRoundAsync(task,Save);
        await Assert.ThrowsAsync<IOException>(()=>crawler.RunRoundAsync(task,(_,_)=>throw new IOException("publish unavailable")));
        Assert.Equal(1,(await resumed.StateAsync(task.Id)).Pending);
        var final=await crawler.RunRoundAsync(task,Save);Assert.True(final.Finished);Assert.False(final.Partial);Assert.Equal(scan,final.ScanId);Assert.Single(rows,r=>r.Kind==InventoryRecordKind.Software);Assert.True(rows.Last().Complete);
        await Assert.ThrowsAsync<InvalidDataException>(()=>crawler.RunRoundAsync(task with{WorkPerRound=2},Save));
    }
    [Fact]
    public async Task WorkAndExclusionBudgetsProducePartialCompletionWithCoverageEvidence()
    {
        using var temp=new TestLedger();Directory.CreateDirectory(temp.DirectoryPath);File.WriteAllText(Path.Combine(temp.DirectoryPath,"a.exe"),"fixture");File.WriteAllText(Path.Combine(temp.DirectoryPath,"b.exe"),"fixture");
        string scans=Path.Combine(temp.DirectoryPath,"excluded");Directory.CreateDirectory(scans);File.WriteAllText(Path.Combine(scans,"hidden.exe"),"fixture");
        await using var journal=SqliteCrawlerJournal.Open(Path.Combine(temp.DirectoryPath,"crawl.db"));var rows=new List<InventoryRecord>();
        var task=new CrawlerTask{Id="limited",Root=temp.DirectoryPath,ExcludedDirectories=[scans],MaximumWorkItems=2,WorkPerRound=100,DelayMilliseconds=0};
        var result=await new InventoryCrawler(journal,new ArtifactInspector()).RunRoundAsync(task,(r,_)=>{rows.Add(r);return Task.CompletedTask;});
        Assert.True(result.Finished);Assert.True(result.Partial);Assert.Contains(rows,r=>r.Coverage?.Code=="CrawlerWorkBudgetExceeded");Assert.False(rows.Last().Complete);
    }
    [Theory][InlineData("zip")][InlineData("tar")][InlineData("gz")]
    public async Task SupportedArchivesAreInspectedWithoutExtraction(string type)
    {
        using var temp=new TestLedger();Directory.CreateDirectory(temp.DirectoryPath);string path=Path.Combine(temp.DirectoryPath,"bundle."+type);
        if(type=="zip")File.WriteAllBytes(path,Zip(("lib/portable.exe",Encoding.UTF8.GetBytes("fixture"))));
        else if(type=="tar"){using var stream=File.Create(path);using var writer=new TarWriter(stream);writer.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile,"lib/portable.exe"){DataStream=new MemoryStream(Encoding.UTF8.GetBytes("fixture"))});}
        else{path=Path.Combine(temp.DirectoryPath,"portable.exe.gz");using var stream=File.Create(path);using var gzip=new GZipStream(stream,CompressionLevel.Fastest);gzip.Write(Encoding.UTF8.GetBytes("fixture"));}
        var rows=await Read(path,new(){Id="archive",Root=temp.DirectoryPath});var artifact=Assert.Single(rows,r=>r.Artifact is not null).Artifact!;Assert.Equal(path,artifact.Location);Assert.Contains("portable.exe",artifact.MemberPath);Assert.False(artifact.ReportedRunning);Assert.Equal(64,artifact.Sha256!.Length);
    }
    [Fact]
    public async Task NestedJarPackageMetadataRetainsOuterAndMemberProvenance()
    {
        using var temp=new TestLedger();Directory.CreateDirectory(temp.DirectoryPath);string path=Path.Combine(temp.DirectoryPath,"outer.zip");
        File.WriteAllBytes(path,Zip(("dependencies/widget.jar",Zip(("META-INF/maven/vendor/widget/pom.properties",Encoding.UTF8.GetBytes("groupId=vendor\nartifactId=widget\nversion=1.2.3\n"))))));
        var artifact=Assert.Single(await Read(path,new(){Id="nested",Root=temp.DirectoryPath}),r=>r.Artifact is not null).Artifact!;
        Assert.Equal("vendor",artifact.Publisher);Assert.Equal("widget",artifact.Product);Assert.Equal("1.2.3",artifact.PackageVersion);Assert.Contains("widget.jar!",artifact.MemberPath);
    }
    [Theory][InlineData("unsafe")][InlineData("expanded")][InlineData("depth")][InlineData("malformed")][InlineData("entries")]
    public async Task HostileOrUnsupportedArchivesProduceBoundedCoverage(string scenario)
    {
        using var temp=new TestLedger();Directory.CreateDirectory(temp.DirectoryPath);string path=Path.Combine(temp.DirectoryPath,"hostile.zip");var task=new CrawlerTask{Id="hostile",Root=temp.DirectoryPath,MaximumEntryBytes=1024,MaximumExpandedBytes=2048};
        byte[] bytes=scenario switch
        {
            "unsafe"=>Zip(("../escape.exe",[1])),"expanded"=>Zip(("huge.exe",new byte[4096])),"depth"=>Zip(("child.zip",Zip(("a.exe",[1])))),
            "entries"=>Zip(("a.exe",[1]),("b.exe",[2])),_=>Encoding.UTF8.GetBytes("invalid archive")
        };
        if(scenario=="depth")task=task with{MaximumArchiveDepth=0};if(scenario=="entries")task=task with{MaximumArchiveEntries=1};File.WriteAllBytes(path,bytes);
        var rows=await Read(path,task);Assert.Contains(rows,r=>r.Issue is not null);Assert.False(File.Exists(Path.Combine(temp.DirectoryPath,"escape.exe")));
    }
    [Fact]
    public async Task LockedAndVanishedFilesProduceCoverageInsteadOfCompletingConfidently()
    {
        using var temp=new TestLedger();string root=Path.Combine(temp.DirectoryPath,"root");Directory.CreateDirectory(root);string path=Path.Combine(root,"locked.exe");File.WriteAllText(path,"fixture");
        await using var journal=SqliteCrawlerJournal.Open(Path.Combine(temp.DirectoryPath,"crawler.db"));var rows=new List<InventoryRecord>();Task Save(InventoryRecord r,CancellationToken _){rows.Add(r);return Task.CompletedTask;}
        var task=new CrawlerTask{Id="locked",Root=root,WorkPerRound=1,DelayMilliseconds=0};var crawler=new InventoryCrawler(journal,new ArtifactInspector());await crawler.RunRoundAsync(task,Save);
        using(var locked=File.Open(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None)){var result=await crawler.RunRoundAsync(task,Save);Assert.True(result.Partial);}
        Assert.Contains(rows,r=>r.Kind==InventoryRecordKind.Coverage);
    }
    [Fact]
    public async Task PassivePeInspectionReturnsRawVersionFieldsWithoutExecutingTheFile()
    {
        var inspector=new ArtifactInspector();var result=await inspector.InspectAsync(typeof(SoftwareCrawlerTests).Assembly.Location);
        Assert.Equal("Mrbr.Bastion.Tests",result.Product);Assert.NotNull(result.ProductVersion);Assert.NotNull(result.FileVersion);Assert.NotNull(result.Architecture);Assert.Equal(64,result.Sha256!.Length);
        var unknown=inspector.InspectBytes("unknown.exe","member",new byte[]{0,1,2});Assert.Null(unknown.ProductVersion);Assert.NotNull(unknown.Sha256);
        await Assert.ThrowsAsync<InvalidDataException>(()=>new ArtifactInspector(100).InspectAsync(typeof(SoftwareCrawlerTests).Assembly.Location));
    }
    [Fact]
    public async Task WindowsBaselinePreservesProcessLifetimesAndDoesNotInventInaccessibleEvidence()
    {
        if(!OperatingSystem.IsWindows())return;var source=new WindowsInventorySource(new ArtifactInspector());bool own=false;var kinds=new HashSet<InventoryRecordKind>();
        await foreach(var row in source.ProcessesAsync()){InventoryJson.Validate(row);kinds.Add(row.Kind);if(row.Artifact?.ProcessId==Environment.ProcessId){own=true;Assert.NotNull(row.Artifact.ProcessStartedUtc);Assert.True(row.Artifact.ReportedRunning);}}
        Assert.True(own);Assert.Contains(InventoryRecordKind.ScanCompleted,kinds);
        var registry=source.Installed().ToArray();Assert.Contains(registry,r=>r.Kind==InventoryRecordKind.ScanCompleted);Assert.All(registry,InventoryJson.Validate);
    }
    private static byte[] Zip(params(string Name,byte[] Bytes)[] entries)
    {using var output=new MemoryStream();using(var archive=new ZipArchive(output,ZipArchiveMode.Create,true))foreach(var entry in entries){using var stream=archive.CreateEntry(entry.Name,CompressionLevel.Fastest).Open();stream.Write(entry.Bytes);}return output.ToArray();}
    private static async Task<ArchiveObservation[]> Read(string path,CrawlerTask task){var rows=new List<ArchiveObservation>();await foreach(var row in new ArchiveInventory(new ArtifactInspector(),task).ReadAsync(path))rows.Add(row);return rows.ToArray();}
}
