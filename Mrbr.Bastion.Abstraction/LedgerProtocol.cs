using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mrbr.Bastion.Abstraction;

/// <summary>Versioned canonical encoding shared by cache writers and future ingest receivers.</summary>
public static class LedgerProtocol
{
    /// <summary>The supported block and receipt version.</summary>
    public const int Version = 1;
    /// <summary>The format of telemetry payloads produced by this version.</summary>
    public const string PayloadFormat = "mrbr.bastion.events+json;v=1";
    /// <summary>Opt-in, versioned software inventory observations.</summary>
    public const string InventoryPayloadFormat = "mrbr.bastion.inventory+json;v=1";
    /// <summary>The chain predecessor of the first block.</summary>
    public static string GenesisHash { get; } = new('0', 64);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly Encoding CanonicalUtf8 = new UTF8Encoding(false, true);

    /// <summary>Serializes validated telemetry. The returned bytes, rather than reserialized objects, are signed.</summary>
    public static byte[] SerializeEvents(IReadOnlyList<TelemetryEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);
        ValidateEvents(events);
        return JsonSerializer.SerializeToUtf8Bytes(events, JsonOptions);
    }

    /// <summary>Reads a previously verified block's events. Call VerifyBlock before parsing untrusted payloads.</summary>
    public static IReadOnlyList<TelemetryEvent> DeserializeEvents(SignedTelemetryBlock block)
    {
        ArgumentNullException.ThrowIfNull(block);
        ValidateContent(block.Content);
        if (block.Content.PayloadFormat != PayloadFormat) throw new InvalidDataException("This block does not contain telemetry events.");
        var events = JsonSerializer.Deserialize<TelemetryEvent[]>(block.Content.Payload, JsonOptions)
            ?? throw new InvalidDataException("The telemetry payload is null.");
        ValidateEvents(events);
        if (events.Length != block.Content.EventCount)
            throw new InvalidDataException("The signed event count does not match the payload.");
        return events;
    }

    /// <summary>Encodes every immutable block field using length-prefixed UTF-8 and little-endian integers.</summary>
    public static byte[] EncodeBlock(TelemetryBlockContent content)
    {
        ValidateContent(content);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, CanonicalUtf8, leaveOpen: true);
        writer.Write("Mrbr.Bastion.Block.v1");
        writer.Write(content.Version);
        writer.Write(content.NodeId);
        writer.Write(content.LedgerId.ToByteArray());
        writer.Write(content.BlockId.ToByteArray());
        writer.Write(content.SequenceNumber);
        writer.Write(content.CreatedUtc.UtcTicks);
        writer.Write(Convert.FromHexString(content.PreviousBlockHash));
        writer.Write(content.PayloadFormat);
        writer.Write(content.EventCount);
        writer.Write(content.Algorithm);
        writer.Write(content.KeyId);
        writer.Write(content.Payload.Length);
        writer.Write(content.Payload);
        writer.Flush();
        return stream.ToArray();
    }

    /// <summary>Encodes receipt identity, block hash, acceptance time, and signing metadata in a separate domain.</summary>
    public static byte[] EncodeReceipt(SettlementReceiptContent content)
    {
        ArgumentNullException.ThrowIfNull(content);
        ValidateIdentity(content.Version, content.NodeId, content.LedgerId, content.BlockId,
            content.SequenceNumber, content.AcceptedUtc, content.Algorithm, content.KeyId);
        ValidateHash(content.BlockHash);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, CanonicalUtf8, leaveOpen: true);
        writer.Write("Mrbr.Bastion.Receipt.v1");
        writer.Write(content.Version);
        writer.Write(content.NodeId);
        writer.Write(content.LedgerId.ToByteArray());
        writer.Write(content.BlockId.ToByteArray());
        writer.Write(content.SequenceNumber);
        writer.Write(Convert.FromHexString(content.BlockHash));
        writer.Write(content.AcceptedUtc.UtcTicks);
        writer.Write(content.Algorithm);
        writer.Write(content.KeyId);
        writer.Flush();
        return stream.ToArray();
    }

    /// <summary>Verifies the block hash and signature before any payload deserialization.</summary>
    public static bool VerifyBlock(SignedTelemetryBlock block, ISignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(block);
        ArgumentNullException.ThrowIfNull(verifier);
        try
        {
            if (block.Signature is not { Length: > 0 and <= 65536 }) return false;
            var bytes = EncodeBlock(block.Content);
            return string.Equals(block.BlockHash, Convert.ToHexString(SHA256.HashData(bytes)), StringComparison.Ordinal)
                && verifier.Verify(block.Content.Algorithm, block.Content.KeyId, bytes, block.Signature);
        }
        catch (InvalidDataException) { return false; }
    }

    /// <summary>Checks a receipt against explicitly trusted receiver keys.</summary>
    public static bool VerifyReceipt(SettlementReceipt receipt, ISignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(verifier);
        if (receipt.Content is null) return false;
        try
        {
            return receipt.Signature is { Length: > 0 and <= 65536 }
                && verifier.Verify(receipt.Content.Algorithm, receipt.Content.KeyId,
                    EncodeReceipt(receipt.Content), receipt.Signature);
        }
        catch (InvalidDataException) { return false; }
    }

    private static void ValidateContent(TelemetryBlockContent content)
    {
        if (content is null) throw new InvalidDataException("Missing block content.");
        ValidateIdentity(content.Version, content.NodeId, content.LedgerId, content.BlockId,
            content.SequenceNumber, content.CreatedUtc, content.Algorithm, content.KeyId);
        ValidateHash(content.PreviousBlockHash);
        if ((content.PayloadFormat != PayloadFormat && content.PayloadFormat != InventoryPayloadFormat) || content.EventCount is < 1 or > 10000
            || content.Payload is not { Length: > 0 and <= 67108864 })
            throw new InvalidDataException("Unsupported or oversized telemetry payload.");
    }

    private static void ValidateIdentity(int version, string nodeId, Guid ledgerId, Guid blockId,
        long sequence, DateTimeOffset time, string algorithm, string keyId)
    {
        if (version != Version || ledgerId == Guid.Empty || blockId == Guid.Empty || sequence < 1
            || time == default || time.Offset != TimeSpan.Zero)
            throw new InvalidDataException("Invalid protocol version, identity, sequence, or UTC time.");
        ValidateText(nodeId, 256);
        ValidateText(algorithm, 128);
        ValidateText(keyId, 256);
    }

    private static void ValidateText(string value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
            throw new InvalidDataException("Missing or oversized protocol metadata.");
        try { _ = CanonicalUtf8.GetByteCount(value); }
        catch (EncoderFallbackException error) { throw new InvalidDataException("Protocol metadata must contain valid Unicode.", error); }
    }

    private static void ValidateHash(string value)
    {
        if (value is not { Length: 64 } || value.Any(c => !char.IsAsciiHexDigit(c))
            || value != value.ToUpperInvariant())
            throw new InvalidDataException("Hashes must be uppercase SHA-256 hexadecimal values.");
    }

    private static void ValidateEvents(IReadOnlyList<TelemetryEvent> events)
    {
        if (events.Count is < 1 or > 10000) throw new InvalidDataException("A block must contain 1 to 10000 events.");
        foreach (var item in events)
        {
            if (item is null || item.EventId == Guid.Empty || !Enum.IsDefined(item.Kind)
                || item.TimestampUtc == default || item.TimestampUtc.Offset != TimeSpan.Zero || item.ProcessId < -1)
                throw new InvalidDataException("An event has an invalid identity, kind, time, or PID.");
            if (item.ParentProcess is { } parent)
            {
                parent.Validate(item.ProcessId, item.ProcessInstanceId, item.TimestampUtc);
                if (item.ProcessInstanceId is null || item.ProcessInstanceId == Guid.Empty
                    || item.ParentProcessId != parent.ProcessId || item.ParentProcessInstanceId != parent.ProcessInstanceId)
                    throw new InvalidDataException("Parent context does not match the event's process identities.");
            }
        }
    }
}
