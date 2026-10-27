using System.ComponentModel;
using System.Diagnostics;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Core;

/// <summary>A PID bound to a Windows/OS process lifetime, rather than to a reusable number alone.</summary>
public sealed record FileIoProcessIdentity(int ProcessId, long StartedUtcTicks)
{
    public static FileIoProcessIdentity Capture(Process process) => new(process.Id, process.StartTime.ToUniversalTime().Ticks);
}

/// <summary>
/// Suppresses file I/O from explicitly managed, live process identities before queue admission.
/// Process lifecycle events, descendants and access by other processes remain observable.
/// This is noise control, not an authorization or intrusion-detection boundary.
/// </summary>
public sealed class ProcessFileIoFilter : IDisposable
{
    private readonly int _collectorProcessId;
    private readonly object _gate = new();
    private Dictionary<int, Process> _managed = [];

    public ProcessFileIoFilter(int collectorProcessId)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(collectorProcessId);
        _collectorProcessId = collectorProcessId;
    }

    public void Update(IReadOnlyList<FileIoProcessIdentity> identities)
    {
        ArgumentNullException.ThrowIfNull(identities);
        if (identities.Count > 64 || identities.Any(i => i is null || i.ProcessId <= 0 || i.StartedUtcTicks <= 0)
            || identities.Select(i => i.ProcessId).Distinct().Count() != identities.Count)
            throw new ArgumentException("At most 64 distinct process lifetime identities are supported.", nameof(identities));
        var next = new Dictionary<int, Process>();
        try
        {
            foreach (var identity in identities)
            {
                Process? process = null;
                try
                {
                    process = Process.GetProcessById(identity.ProcessId);
                    _ = process.SafeHandle; // Retain the OS lifetime; later checks must not reopen a reused PID.
                    if (!process.HasExited && process.StartTime.ToUniversalTime().Ticks == identity.StartedUtcTicks)
                    { next.Add(identity.ProcessId, process); process = null; }
                }
                catch (ArgumentException) { } // Already exited. Never transfer an exclusion to a reused PID.
                catch (InvalidOperationException) { }
                catch (Win32Exception) { } // An identity that cannot be verified is retained, not silently hidden.
                finally { process?.Dispose(); }
            }
            lock (_gate)
            {
                var previous = _managed; _managed = next; next = previous;
            }
        }
        finally { foreach (var process in next.Values) process.Dispose(); }
    }

    public bool Retain(TelemetryEvent item)
    {
        if (!IsFileEvent(item.Kind)) return true;
        return RetainProcess(item.ProcessId);
    }

    /// <summary>Use only for file I/O: lifecycle events must bypass this predicate.</summary>
    public bool RetainProcess(int processId)
    {
        if (processId == _collectorProcessId) return false;
        lock (_gate)
        {
            if (!_managed.TryGetValue(processId, out var process)) return true;
            try { return process.HasExited; }
            catch (InvalidOperationException) { return true; }
            catch (Win32Exception) { return true; }
        }
    }
    public int ManagedProcessCount { get { lock (_gate) return _managed.Count; } }

    internal static bool IsFileEvent(TelemetryEventKind kind) => kind is TelemetryEventKind.FileOpened or TelemetryEventKind.FileRead
        or TelemetryEventKind.FileWritten or TelemetryEventKind.FileClosed or TelemetryEventKind.FileDeleted
        or TelemetryEventKind.FileRenamed or TelemetryEventKind.FileMetadataQueried;

    public void Dispose()
    {
        lock (_gate)
        {
            foreach (var process in _managed.Values) process.Dispose();
            _managed.Clear();
        }
    }
}
