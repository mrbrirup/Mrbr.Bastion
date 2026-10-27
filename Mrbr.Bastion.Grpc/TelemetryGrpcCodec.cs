using Google.Protobuf;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Grpc.Protocol;

namespace Mrbr.Bastion.Grpc;

/// <summary>Maps wire fields to the existing canonical signature model without reserializing payloads.</summary>
public static class TelemetryGrpcCodec
{
    public static SignedBlock ToProto(SignedTelemetryBlock block)
    {
        var c = block.Content;
        return new SignedBlock
        {
            Version = c.Version, NodeId = c.NodeId, LedgerId = c.LedgerId.ToString("D"), BlockId = c.BlockId.ToString("D"),
            SequenceNumber = c.SequenceNumber, CreatedUtcTicks = c.CreatedUtc.UtcTicks, PreviousBlockHash = c.PreviousBlockHash,
            PayloadFormat = c.PayloadFormat, EventCount = c.EventCount, Algorithm = c.Algorithm, KeyId = c.KeyId,
            Payload = ByteString.CopyFrom(c.Payload), BlockHash = block.BlockHash, Signature = ByteString.CopyFrom(block.Signature)
        };
    }
    public static SignedTelemetryBlock FromProto(SignedBlock block)
    {
        if (block.Payload.Length > 4 * 1024 * 1024 || block.Signature.Length > 65536) throw new TelemetryMessageTooLargeException();
        return new(new(block.Version, block.NodeId, Identifier(block.LedgerId), Identifier(block.BlockId), block.SequenceNumber,
            UtcTime(block.CreatedUtcTicks), block.PreviousBlockHash, block.PayloadFormat, block.EventCount,
            block.Algorithm, block.KeyId, block.Payload.ToByteArray()), block.BlockHash, block.Signature.ToByteArray());
    }
    public static SignedReceipt ToProto(SettlementReceipt receipt)
    {
        var c = receipt.Content;
        return new SignedReceipt
        {
            Version = c.Version, NodeId = c.NodeId, LedgerId = c.LedgerId.ToString("D"), BlockId = c.BlockId.ToString("D"),
            SequenceNumber = c.SequenceNumber, BlockHash = c.BlockHash, AcceptedUtcTicks = c.AcceptedUtc.UtcTicks,
            Algorithm = c.Algorithm, KeyId = c.KeyId, Signature = ByteString.CopyFrom(receipt.Signature)
        };
    }
    public static SettlementReceipt FromProto(SignedReceipt receipt)
    {
        if (receipt.Signature.Length > 65536) throw new TelemetryMessageTooLargeException();
        return new(new(receipt.Version, receipt.NodeId, Identifier(receipt.LedgerId), Identifier(receipt.BlockId),
            receipt.SequenceNumber, receipt.BlockHash, UtcTime(receipt.AcceptedUtcTicks), receipt.Algorithm, receipt.KeyId), receipt.Signature.ToByteArray());
    }
    private static Guid Identifier(string text) => Guid.TryParseExact(text, "D", out var id) && id != Guid.Empty
        ? id : throw new InvalidDataException("An identifier is not a nonempty GUID in D format.");
    private static DateTimeOffset UtcTime(long ticks)
    {
        try { return new DateTimeOffset(ticks, TimeSpan.Zero); }
        catch (ArgumentOutOfRangeException error) { throw new InvalidDataException("The UTC timestamp is invalid.", error); }
    }
}
