using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Core;

internal sealed record ProcessObservation(Guid InstanceId, int ParentProcessId,
    DateTimeOffset FirstObservedUtc, string? ExecutablePath, string? CommandLine, string? ProcessName,
    DateTimeOffset? StartedUtc, ProcessParent? ParentProcess)
{
    public Guid? ParentInstanceId => ParentProcess?.ProcessInstanceId;
}

/// <summary>Used only on the ETW dispatch thread. A new start always creates a new lifetime for a reused PID.</summary>
internal sealed class ProcessTracker
{
    private readonly Dictionary<int, ProcessObservation> _processes = new();

    public ProcessObservation Observe(int pid, int parentPid, DateTimeOffset time,
        string? executablePath, string? commandLine, bool snapshot, string? processName = null)
    {
        _processes.TryGetValue(pid, out var known);
        if (snapshot && known is not null && known.FirstObservedUtc <= time) return known;

        // Rundown time is not creation time: the recorded parent PID may already have been reused.
        // Only a live creation event can bind a child to a parent lifetime observed by this collector.
        var parent = !snapshot && parentPid > 0 && parentPid != pid ? Find(parentPid, time) : null;
        var context = parent is null ? null : new ProcessParent(parentPid, parent.InstanceId,
            parent.FirstObservedUtc, parent.StartedUtc, parent.ProcessName, parent.ExecutablePath);
        var process = new ProcessObservation(Guid.NewGuid(), parentPid, time, executablePath, commandLine,
            processName, snapshot ? null : time, context);
        // A delayed start must not displace the newer lifetime currently occupying this PID.
        if (known is null || known.FirstObservedUtc <= time) _processes[pid] = process;
        return process;
    }

    public ProcessObservation? Find(int pid, DateTimeOffset time) =>
        _processes.TryGetValue(pid, out var process) && process.FirstObservedUtc <= time ? process : null;

    public ProcessObservation? Stop(int pid, DateTimeOffset time)
    {
        var process = Find(pid, time);
        if (process is not null) _processes.Remove(pid);
        return process;
    }
}
