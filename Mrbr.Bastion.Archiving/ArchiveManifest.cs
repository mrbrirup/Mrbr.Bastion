using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Archiving;

/// <summary>A signed, ordered segment of a ledger. Original block and receipt bytes remain in the file.</summary>
public sealed record ArchiveManifestContent(int Version, Guid ArchiveId, string NodeId, Guid LedgerId,
    long FirstSequence, long LastSequence, string PreviousBlockHash, string TailBlockHash,
    long PayloadBytes, long DataBytes, string DataHash, string PreviousArchiveHash, string Algorithm, string KeyId);
public sealed record SignedArchiveManifest(ArchiveManifestContent Content, string ManifestHash, byte[] Signature);
public sealed record ArchiveEntry(byte[] BlockJson, byte[] ReceiptJson);
public sealed record VerifiedArchiveEntry(SignedTelemetryBlock Block, SettlementReceipt Receipt, byte[] BlockJson, byte[] ReceiptJson);
public sealed record ArchiveSegment(string FileName, long FileBytes, SignedArchiveManifest Manifest);

public static class ArchiveProtocol
{
    public const int MaximumManifestBytes = 128 * 1024;
    public const int MaximumBodyBytes = 2 * 64 * 1024 * 1024 + 131072;
    public const long MaximumFileBytes = 2L * 1024 * 1024 * 1024;
    public static JsonSerializerOptions Json { get; } = new(JsonSerializerDefaults.Web)
    { PropertyNameCaseInsensitive = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 12 };
    public static string FileName(Guid id) => id.ToString("N") + ".bastion-archive";
    public static byte[] Encode(ArchiveManifestContent c)
    {
        try { return EncodeCore(c); }
        catch (EncoderFallbackException error) { throw new InvalidDataException("Archive metadata must contain valid Unicode.",error); }
    }
    private static byte[] EncodeCore(ArchiveManifestContent c)
    {
        if (c is null || c.Version != 1 || c.ArchiveId == Guid.Empty || c.LedgerId == Guid.Empty
            || string.IsNullOrWhiteSpace(c.NodeId) || c.NodeId.Length > 256 || c.FirstSequence < 1
            || c.LastSequence < c.FirstSequence || c.LastSequence - c.FirstSequence >= 10000
            || c.PayloadBytes < 1 || c.DataBytes < 8 || c.DataBytes > MaximumFileBytes || c.PayloadBytes > c.DataBytes
            || string.IsNullOrWhiteSpace(c.Algorithm) || c.Algorithm.Length > 128
            || string.IsNullOrWhiteSpace(c.KeyId) || c.KeyId.Length > 256)
            throw new InvalidDataException("Invalid archive manifest.");
        using var stream = new MemoryStream();
        using var w = new BinaryWriter(stream, new UTF8Encoding(false, true), true);
        w.Write("Mrbr.Bastion.Archive.v1"); w.Write(c.Version); w.Write(c.ArchiveId.ToByteArray());
        w.Write(c.NodeId); w.Write(c.LedgerId.ToByteArray()); w.Write(c.FirstSequence); w.Write(c.LastSequence);
        void Hash(string value)
        {
            if (value is not { Length: 64 } || value.Any(ch => !char.IsAsciiHexDigit(ch)) || value != value.ToUpperInvariant())
                throw new InvalidDataException("Invalid archive hash.");
            w.Write(Convert.FromHexString(value));
        }
        Hash(c.PreviousBlockHash); Hash(c.TailBlockHash); w.Write(c.PayloadBytes); w.Write(c.DataBytes);
        Hash(c.DataHash); Hash(c.PreviousArchiveHash); w.Write(c.Algorithm); w.Write(c.KeyId); w.Flush();
        return stream.ToArray();
    }
    public static void VerifyManifest(SignedArchiveManifest manifest, ISignatureVerifier verifier)
    {
        if (manifest is null || manifest.Signature is not { Length: > 0 and <= 65536 }) throw new InvalidDataException("Missing archive proof.");
        var bytes = Encode(manifest.Content);
        if (manifest.ManifestHash != Convert.ToHexString(SHA256.HashData(bytes))
            || !verifier.Verify(manifest.Content.Algorithm, manifest.Content.KeyId, bytes, manifest.Signature))
            throw new InvalidDataException("Archive manifest hash or signature failed verification.");
    }
    public static T Decode<T>(byte[] bytes)
    {
        try { return JsonSerializer.Deserialize<T>(bytes, Json) ?? throw new InvalidDataException("Null archive record."); }
        catch (JsonException error) { throw new InvalidDataException("Malformed archive record.", error); }
    }
    public static VerifiedArchiveEntry VerifyEntry(ArchiveEntry entry, ISignatureVerifier blockVerifier,
        ISignatureVerifier receiptVerifier, IEnumerable<IBlockPayloadCodec> codecs)
    {
        if (entry.BlockJson is not { Length: > 0 and <= MaximumBodyBytes }
            || entry.ReceiptJson is not { Length: > 0 and <= TelemetryJson.MaximumReceiptBytes }) throw new InvalidDataException("Oversized archive record.");
        var block = Decode<SignedTelemetryBlock>(entry.BlockJson); var receipt = Decode<SettlementReceipt>(entry.ReceiptJson);
        if (!LedgerProtocol.VerifyBlock(block, blockVerifier) || !LedgerProtocol.VerifyReceipt(receipt, receiptVerifier))
            throw new InvalidDataException("Archived block or settlement signature failed verification.");
        BlockPayloadValidation.Validate(block, codecs);
        var c = block.Content; var r = receipt.Content;
        if (r.NodeId != c.NodeId || r.LedgerId != c.LedgerId || r.BlockId != c.BlockId
            || r.SequenceNumber != c.SequenceNumber || r.BlockHash != block.BlockHash)
            throw new InvalidDataException("The archive receipt does not settle its exact block.");
        return new(block, receipt, entry.BlockJson, entry.ReceiptJson);
    }
}
