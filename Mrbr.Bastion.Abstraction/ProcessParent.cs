namespace Mrbr.Bastion.Abstraction;

/// <summary>
/// A copy of the reported parent's observed lifetime at a child's creation event.
/// This is historical context, not a lookup of the process currently using the parent PID.
/// Windows may designate a parent other than the process that requested creation.
/// </summary>
public sealed record ProcessParent(int ProcessId, Guid ProcessInstanceId, DateTimeOffset FirstObservedUtc,
    DateTimeOffset? StartedUtc = null, string? ProcessName = null, string? ExecutablePath = null)
{
    /// <summary>Validates bounded parent context without inferring missing identity or start times.</summary>
    public void Validate(int childProcessId, Guid? childInstanceId, DateTimeOffset observedUtc)
    {
        if (childProcessId <= 0 || ProcessId <= 0 || ProcessId == childProcessId || ProcessInstanceId == Guid.Empty
            || ProcessInstanceId == childInstanceId || FirstObservedUtc == default
            || FirstObservedUtc.Offset != TimeSpan.Zero || FirstObservedUtc > observedUtc
            || StartedUtc is { } started && (started == default || started.Offset != TimeSpan.Zero || started > FirstObservedUtc)
            || ProcessName?.Length > 512 || ExecutablePath?.Length > 32768)
            throw new InvalidDataException("Invalid parent process context.");
    }
}
