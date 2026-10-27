using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Inventory.Windows;

public sealed class WindowsInventorySource(IArtifactInspector inspector)
{
    public async IAsyncEnumerable<InventoryRecord> ProcessesAsync([EnumeratorCancellation]CancellationToken cancellationToken=default)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows process inventory requires Windows.");
        Guid scan=Guid.NewGuid();bool complete=true;
        InventoryRecord Record(InventoryRecordKind kind,SoftwareArtifact? a=null,InventoryCoverage? c=null,bool done=false)=>new(1,Guid.NewGuid(),scan,"process-baseline",InventorySource.RunningProcess,kind,DateTimeOffset.UtcNow,"running-processes",a,c,done);
        yield return Record(InventoryRecordKind.ScanStarted);
        foreach(var process in Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();SoftwareArtifact? artifact=null;InventoryCoverage? coverage=null;
            using(process)
            try
            {
                int pid=process.Id;DateTimeOffset started=process.StartTime.ToUniversalTime();string? path=process.MainModule?.FileName;
                if(path is null)throw new IOException("ExecutablePathUnavailable");
                artifact=(await inspector.InspectAsync(path,cancellationToken)) with{ProcessId=pid,ProcessStartedUtc=started,ReportedRunning=true};
                if(process.HasExited || process.StartTime.ToUniversalTime()!=started.UtcDateTime)throw new IOException("ProcessChangedDuringObservation");
            }
            catch(OperationCanceledException){throw;}
            catch(Exception e)when(e is System.ComponentModel.Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException or InvalidDataException)
            {complete=false;coverage=new("ProcessEvidenceUnavailable",$"pid:{process.Id}");}
            if(coverage is not null)yield return Record(InventoryRecordKind.Coverage,c:coverage);
            else if(artifact is not null)yield return Record(InventoryRecordKind.Software,artifact);
        }
        yield return Record(InventoryRecordKind.ScanCompleted,done:complete);
    }
    public async Task<InventoryRecord?> EnrichProcessEventAsync(TelemetryEvent observation,CancellationToken cancellationToken=default)
    {
        if(observation.Kind is not (TelemetryEventKind.ProcessStarted or TelemetryEventKind.ProcessSnapshot or TelemetryEventKind.ProcessStopped))return null;
        if(observation.ProcessInstanceId is null)return null;
        SoftwareArtifact artifact;
        if(observation.Kind==TelemetryEventKind.ProcessStopped)artifact=new(observation.ExecutablePath??$"pid:{observation.ProcessId}");
        else
        {
            using var process=Process.GetProcessById(observation.ProcessId);DateTimeOffset started=process.StartTime.ToUniversalTime();
            if(started>observation.TimestampUtc.AddMilliseconds(100)||observation.Kind==TelemetryEventKind.ProcessStarted&&observation.TimestampUtc-started>TimeSpan.FromSeconds(5))throw new IOException("ProcessLifetimeUncertain");
            string path=process.MainModule?.FileName??throw new IOException("ExecutablePathUnavailable");
            artifact=await inspector.InspectAsync(path,cancellationToken);
            if(process.HasExited||process.StartTime.ToUniversalTime()!=started.UtcDateTime)throw new IOException("ProcessChangedDuringObservation");
            artifact=artifact with{ProcessStartedUtc=started};
        }
        return new(1,observation.EventId,observation.ProcessInstanceId.Value,"process-events",InventorySource.RunningProcess,
            observation.Kind==TelemetryEventKind.ProcessStopped?InventoryRecordKind.ProcessStopped:InventoryRecordKind.Software,observation.TimestampUtc,"process-events",
            artifact with {ProcessId=observation.ProcessId,ProcessInstanceId=observation.ProcessInstanceId,
                ParentProcessId=observation.ParentProcessId is >=0?observation.ParentProcessId:null,ParentProcess=observation.ParentProcess,
                ReportedRunning=observation.Kind!=TelemetryEventKind.ProcessStopped});
    }
    public IEnumerable<InventoryRecord> Installed(bool includeCurrentUser=false)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Registry inventory requires Windows.");
        return ReadRegistry(includeCurrentUser);
    }
    [SupportedOSPlatform("windows")]
    private static IEnumerable<InventoryRecord> ReadRegistry(bool user)
    {
        foreach(var hive in user?new[]{RegistryHive.LocalMachine,RegistryHive.CurrentUser}:new[]{RegistryHive.LocalMachine})
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
        {
            Guid scan=Guid.NewGuid();string scope=hive+"/"+view;bool complete=true;
            InventoryRecord Row(InventoryRecordKind kind,SoftwareArtifact? a=null,InventoryCoverage? c=null,bool done=false)=>new(1,Guid.NewGuid(),scan,"registry",InventorySource.InstalledApplication,kind,DateTimeOffset.UtcNow,scope,a,c,done);
            yield return Row(InventoryRecordKind.ScanStarted);var records=new List<InventoryRecord>();
            try
            {
                using var root=RegistryKey.OpenBaseKey(hive,view);using var uninstall=root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if(uninstall is not null)
                foreach(string name in uninstall.GetSubKeyNames().Take(20001))
                {
                    if(records.Count>=20000){complete=false;records.Add(Row(InventoryRecordKind.Coverage,c:new("RegistryEntryBudgetExceeded",scope)));break;}
                    try
                    {
                        using var entry=uninstall.OpenSubKey(name);string? Get(string key){var v=entry?.GetValue(key) as string;if(v?.Length>512)throw new InvalidDataException("RegistryMetadataBudgetExceeded");return v;}
                        if(Get("DisplayName") is not {} product)continue;
                        records.Add(Row(InventoryRecordKind.Software,new(scope+"/"+name,Publisher:Get("Publisher"),Product:product,PackageVersion:Get("DisplayVersion"))));
                    }
                    catch(Exception e)when(e is UnauthorizedAccessException or System.Security.SecurityException or IOException or InvalidDataException)
                    {complete=false;records.Add(Row(InventoryRecordKind.Coverage,c:new("RegistryEntryUnavailable",scope+"/"+name)));}
                }
            }
            catch(Exception e)when(e is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {complete=false;records.Add(Row(InventoryRecordKind.Coverage,c:new("RegistryScopeUnavailable",scope)));}
            foreach(var record in records)yield return record;
            yield return Row(InventoryRecordKind.ScanCompleted,done:complete);
        }
    }
}
