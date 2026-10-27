using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Archiving;

/// <summary>Write-once files. A caller may publish a catalog reference only after Create and Verify return.</summary>
public static class ArchiveFile
{
    private static ReadOnlySpan<byte> Header => "BASARCH1"u8;
    private static ReadOnlySpan<byte> Trailer => "BASEND01"u8;

    public static ArchiveSegment Create(string directory, IEnumerable<ArchiveEntry> entries, string previousArchiveHash,
        ISignatureSigner signer, ISignatureVerifier blockVerifier, ISignatureVerifier receiptVerifier,
        IEnumerable<IBlockPayloadCodec> codecs, long maximumFileBytes, CancellationToken cancellationToken = default)
    {
        if (maximumFileBytes is < 1024 or > ArchiveProtocol.MaximumFileBytes) throw new ArgumentOutOfRangeException(nameof(maximumFileBytes));
        directory = Path.GetFullPath(directory);
        var createdDirectories = ArchiveDurability.PrepareDirectory(directory);
        var id = Guid.NewGuid(); string name = ArchiveProtocol.FileName(id), path = Path.Combine(directory, name);
        // CreateNew never replaces an existing archive. A crash can leave an unreferenced file, never a pruned gap.
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
        using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            void Write(ReadOnlySpan<byte> bytes) { file.Write(bytes); hash.AppendData(bytes); }
            Write(Header);
            SignedTelemetryBlock? first = null, last = null; long payloadBytes = 0, count = 0;
            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var row = ArchiveProtocol.VerifyEntry(entry, blockVerifier, receiptVerifier, codecs);
                var block = row.Block;
                if (++count > 10000 || last is not null && (block.Content.NodeId != first!.Content.NodeId
                    || block.Content.LedgerId != first.Content.LedgerId || block.Content.SequenceNumber != last.Content.SequenceNumber + 1
                    || block.Content.PreviousBlockHash != last.BlockHash)) throw new InvalidDataException("Archive entries are not one contiguous ledger segment.");
                first ??= block; last = block; payloadBytes = checked(payloadBytes + block.Content.Payload.Length);
                if (file.Position + 8L + entry.BlockJson.Length + entry.ReceiptJson.Length + ArchiveProtocol.MaximumManifestBytes + 12 > maximumFileBytes)
                    throw new IOException("Archive segment byte limit reached; resident evidence was preserved.");
                byte[] length = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(length, entry.BlockJson.Length); Write(length); Write(entry.BlockJson);
                BinaryPrimitives.WriteInt32LittleEndian(length, entry.ReceiptJson.Length); Write(length); Write(entry.ReceiptJson);
            }
            if (first is null || last is null) throw new InvalidDataException("An archive cannot be empty.");
            var content = new ArchiveManifestContent(1, id, first.Content.NodeId, first.Content.LedgerId, first.Content.SequenceNumber,
                last.Content.SequenceNumber, first.Content.PreviousBlockHash, last.BlockHash, payloadBytes, file.Position,
                Convert.ToHexString(hash.GetHashAndReset()), previousArchiveHash, signer.Algorithm, signer.KeyId);
            var encoded = ArchiveProtocol.Encode(content);
            var manifest = new SignedArchiveManifest(content, Convert.ToHexString(SHA256.HashData(encoded)), signer.Sign(encoded));
            byte[] footer = JsonSerializer.SerializeToUtf8Bytes(manifest, ArchiveProtocol.Json);
            if (footer.Length > ArchiveProtocol.MaximumManifestBytes) throw new InvalidDataException("Oversized archive manifest.");
            file.Write(footer); byte[] size = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(size, footer.Length); file.Write(size); file.Write(Trailer);
            file.Flush(flushToDisk: true);
        }
        ArchiveDurability.FlushDirectoryEntries(directory, createdDirectories);
        return Verify(path, blockVerifier, receiptVerifier, codecs, cancellationToken: cancellationToken);
    }

    /// <summary>Callbacks are provisional until the entire file, its manifest and digest have verified successfully.</summary>
    public static ArchiveSegment Verify(string path, ISignatureVerifier blockVerifier, ISignatureVerifier receiptVerifier,
        IEnumerable<IBlockPayloadCodec> codecs, Action<VerifiedArchiveEntry>? observe = null, CancellationToken cancellationToken = default)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        return VerifyOpen(file, path, blockVerifier, receiptVerifier, codecs, observe, cancellationToken);
    }

    public static ArchiveLease OpenVerified(string path, ISignatureVerifier blockVerifier, ISignatureVerifier receiptVerifier,
        IEnumerable<IBlockPayloadCodec> codecs, CancellationToken cancellationToken = default)
    {
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        try { return new(file, path, VerifyOpen(file, path, blockVerifier, receiptVerifier, codecs, null, cancellationToken)); }
        catch { file.Dispose(); throw; }
    }

    internal static ArchiveSegment VerifyOpen(FileStream file, string path, ISignatureVerifier blockVerifier, ISignatureVerifier receiptVerifier,
        IEnumerable<IBlockPayloadCodec> codecs, Action<VerifiedArchiveEntry>? observe, CancellationToken cancellationToken)
    {
        if (file.Length < 24 || file.Length > ArchiveProtocol.MaximumFileBytes) throw new InvalidDataException("Invalid archive file size.");
        byte[] trailer = new byte[12]; file.Position = file.Length - trailer.Length; file.ReadExactly(trailer);
        int length = BinaryPrimitives.ReadInt32LittleEndian(trailer);
        if (!trailer.AsSpan(4).SequenceEqual(Trailer) || length is < 1 or > ArchiveProtocol.MaximumManifestBytes
            || length > file.Length - 20) throw new InvalidDataException("Incomplete archive footer.");
        file.Position = file.Length - 12 - length; long dataEnd = file.Position;
        byte[] footer = new byte[length]; file.ReadExactly(footer);
        var manifest = ArchiveProtocol.Decode<SignedArchiveManifest>(footer); ArchiveProtocol.VerifyManifest(manifest, blockVerifier);
        var c = manifest.Content;
        if (c.DataBytes != dataEnd || Path.GetFileName(path) != ArchiveProtocol.FileName(c.ArchiveId)) throw new InvalidDataException("Archive identity or data length mismatch.");
        file.Position = 0; using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] Read(int size)
        {
            if (size < 0 || size > dataEnd - file.Position) throw new InvalidDataException("Truncated archive data.");
            byte[] bytes = new byte[size]; file.ReadExactly(bytes); hash.AppendData(bytes); return bytes;
        }
        if (!Read(8).AsSpan().SequenceEqual(Header)) throw new InvalidDataException("Unknown archive format.");
        long sequence = c.FirstSequence - 1, payloadBytes = 0; string previous = c.PreviousBlockHash;
        byte[] Body(int maximum)
        {
            int size = BinaryPrimitives.ReadInt32LittleEndian(Read(4));
            if (size < 1 || size > maximum) throw new InvalidDataException("Oversized archive frame.");
            return Read(size);
        }
        while (file.Position < dataEnd)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var entry = new ArchiveEntry(Body(ArchiveProtocol.MaximumBodyBytes), Body(TelemetryJson.MaximumReceiptBytes));
            var row = ArchiveProtocol.VerifyEntry(entry, blockVerifier, receiptVerifier, codecs); var b = row.Block;
            if (sequence == c.LastSequence || b.Content.NodeId != c.NodeId || b.Content.LedgerId != c.LedgerId
                || b.Content.SequenceNumber != checked(sequence + 1) || b.Content.PreviousBlockHash != previous)
                throw new InvalidDataException("Archived ledger sequence or predecessor mismatch.");
            sequence++; previous = b.BlockHash; payloadBytes = checked(payloadBytes + b.Content.Payload.Length); observe?.Invoke(row);
        }
        if (sequence != c.LastSequence || previous != c.TailBlockHash || payloadBytes != c.PayloadBytes
            || Convert.ToHexString(hash.GetHashAndReset()) != c.DataHash) throw new InvalidDataException("Archive digest, range or payload total mismatch.");
        return new(Path.GetFileName(path), file.Length, manifest);
    }
}
