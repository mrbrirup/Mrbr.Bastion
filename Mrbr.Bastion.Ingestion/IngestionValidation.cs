using System.Text.Json;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Ingestion;

public static class IngestionValidation
{
    public static SignedTelemetryBlock VerifyAndCopy(SignedTelemetryBlock block, INodeTrustStore trust, IngestionOptions limits)
    {
        if (block?.Content?.Payload is null || block.Signature is null)
            throw new TelemetryRejectedException(IngestionFailure.InvalidBlock, "Missing block content or signature.");
        if (block.Content.Payload.Length > limits.MaximumPayloadBytes || block.Content.EventCount > limits.MaximumEventsPerBlock
            || block.Signature.Length > 65536)
            throw new TelemetryRejectedException(IngestionFailure.TooLarge, "The block exceeds ingestion limits.");
        var copy = block with { Content = block.Content with { Payload = block.Content.Payload.ToArray() }, Signature = block.Signature.ToArray() };
        var verifier = trust.Resolve(copy.Content.NodeId, copy.Content.LedgerId);
        if (verifier is null || !LedgerProtocol.VerifyBlock(copy, verifier))
            throw new TelemetryRejectedException(IngestionFailure.UntrustedBlock, "The block is not authenticated for an enrolled node and ledger.");
        // Do not deserialize telemetry until the node, hash, signature, and size limits have been checked.
        try { BlockPayloadValidation.Validate(copy, limits.AdditionalPayloadCodecs); }
        catch (Exception error) when (error is JsonException or InvalidDataException)
        { throw new TelemetryRejectedException(IngestionFailure.InvalidBlock, "The signed telemetry payload is invalid."); }
        return copy;
    }
    public static void VerifyReceipt(SettlementReceipt receipt, SignedTelemetryBlock block, ISignatureVerifier verifier)
    {
        if (!LedgerProtocol.VerifyReceipt(receipt, verifier)) throw new InvalidDataException("An ingestion receipt failed signature verification.");
        var proof = receipt.Content;
        var content = block.Content;
        if (proof.NodeId != content.NodeId || proof.LedgerId != content.LedgerId || proof.BlockId != content.BlockId
            || proof.SequenceNumber != content.SequenceNumber || proof.BlockHash != block.BlockHash)
            throw new InvalidDataException("An ingestion receipt does not identify its stored block.");
    }
}
