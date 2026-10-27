namespace Mrbr.Bastion.Core;

public sealed record WindowsEtwOptions
{
    public bool CollectFileEvents { get; init; } = true;
    public bool CollectMetadataQueries { get; init; }
    public bool IncludeExistingProcesses { get; init; } = true;
    /// <summary>Suppress collector I/O to avoid recursively collecting writes to its own outbox.</summary>
    public bool ExcludeCollectorProcess { get; init; } = true;
    /// <summary>Runs before file-event copying/path resolution. Return true to retain a PID's file I/O.</summary>
    public Func<int, bool>? RetainFileIoProcess { get; init; }
    public int BufferSizeMegabytes { get; init; } = 64;
}
