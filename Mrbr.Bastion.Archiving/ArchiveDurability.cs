using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Mrbr.Bastion.Archiving;

internal static class ArchiveDurability
{
    public static string[] PrepareDirectory(string path)
    {
        var created = new List<string>();
        for (var current = new DirectoryInfo(path); current is not null && !current.Exists; current = current.Parent) created.Add(current.FullName);
        Directory.CreateDirectory(path); return created.ToArray();
    }
    public static void FlushDirectoryEntries(string directory, string[] created)
    {
        // Windows WriteThrough + Flush(true) flushes NTFS file metadata. POSIX also needs directory fsync.
        if (OperatingSystem.IsWindows()) return;
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS() && !OperatingSystem.IsFreeBSD())
            throw new PlatformNotSupportedException("Durable archive creation requires Windows or a POSIX filesystem with directory fsync.");
        var directories = created.Select(path => Path.GetDirectoryName(path)!).Append(directory).Distinct(StringComparer.Ordinal);
        foreach (string path in directories)
        {
            int handle = Open(path, 0);
            if (handle < 0) throw new IOException("Could not open archive directory for durable publication.", new Win32Exception(Marshal.GetLastPInvokeError()));
            try { if (Sync(handle) != 0) throw new IOException("Archive directory sync failed; resident evidence was preserved.", new Win32Exception(Marshal.GetLastPInvokeError())); }
            finally { _ = Close(handle); }
        }
    }
    [DllImport("libc", EntryPoint="open", SetLastError=true)] private static extern int Open(string path,int flags);
    [DllImport("libc", EntryPoint="fsync", SetLastError=true)] private static extern int Sync(int handle);
    [DllImport("libc", EntryPoint="close", SetLastError=true)] private static extern int Close(int handle);
}
