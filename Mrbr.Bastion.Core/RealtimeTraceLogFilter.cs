namespace Mrbr.Bastion.Core;

/// <summary>Only System's I/O to this session's exact ETW transport artifact is internal noise.</summary>
internal sealed class RealtimeTraceLogFilter(string windowsDirectory, string sessionName)
{
    private readonly string _path = Path.Combine(windowsDirectory, "System32", "LogFiles", "WMI", "RtBackup", "EtwRT" + sessionName + ".etl").Replace('/', '\\');
    public bool Retain(int processId, string? path)
    {
        if (processId != 4 || path is null) return true;
        string normalized = path.Replace('/', '\\');
        if (normalized.StartsWith(@"\\?\", StringComparison.Ordinal) || normalized.StartsWith(@"\??\", StringComparison.Ordinal)) normalized = normalized[4..];
        return !string.Equals(normalized, _path, StringComparison.OrdinalIgnoreCase);
    }
}
