using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Core;

/// <summary>Creates callbacks once. Process exclusions avoid path lookup; all exclusions avoid copied-event allocation.</summary>
internal sealed class FilteredFileEventDispatcher(Func<int, bool> retainProcess, Func<int, string?, bool>? retainPath = null)
{
    private long _filtered;
    public long FilteredEvents => Interlocked.Read(ref _filtered);

    public Action<T> CreateCallback<T>(Func<T, int> processId, Func<T, TelemetryEvent> copy, Action<TelemetryEvent> publish,
        Func<T, string?>? path = null) => raw =>
    {
        int pid = processId(raw);
        if (!retainProcess(pid) || retainPath is not null && !retainPath(pid, path?.Invoke(raw)))
        { Interlocked.Increment(ref _filtered); return; }
        publish(copy(raw));
    };
}
