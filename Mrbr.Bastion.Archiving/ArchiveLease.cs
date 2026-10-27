using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Archiving;

/// <summary>A verified open file. Windows sharing denies modification/deletion until disposal.</summary>
public sealed class ArchiveLease : IDisposable
{
    private readonly FileStream _file;
    private readonly string _path;
    public ArchiveSegment Segment { get; }
    internal ArchiveLease(FileStream file, string path, ArchiveSegment segment) { _file = file; _path = path; Segment = segment; }
    public void VerifyPath()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Pinned archive verification is Windows-only.");
        using var current = File.OpenHandle(_path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!GetFileInformationByHandle(_file.SafeFileHandle, out var original) || !GetFileInformationByHandle(current, out var now))
            throw new IOException("Could not verify the pinned archive file identity.");
        if (original.VolumeSerialNumber != now.VolumeSerialNumber || original.FileIndexHigh != now.FileIndexHigh
            || original.FileIndexLow != now.FileIndexLow || original.FileSizeHigh != now.FileSizeHigh || original.FileSizeLow != now.FileSizeLow
            || _file.Length != Segment.FileBytes) throw new InvalidDataException("The archive path no longer identifies its verified file.");
    }
    public ArchiveSegment Reverify(ISignatureVerifier blocks, ISignatureVerifier receipts, IEnumerable<IBlockPayloadCodec> codecs,
        Action<VerifiedArchiveEntry>? observe, CancellationToken cancellationToken)
    { lock (_file) { return ArchiveFile.VerifyOpen(_file, _path, blocks, receipts, codecs, observe, cancellationToken); } }
    public void Dispose() => _file.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint FileAttributes; public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
}
