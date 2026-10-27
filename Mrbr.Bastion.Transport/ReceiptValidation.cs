using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Transport;

public static class ReceiptValidation
{
    public static SettlementReceipt Verify(SettlementReceipt receipt, SignedTelemetryBlock block, ISignatureVerifier verifier)
    {
        if (!LedgerProtocol.VerifyReceipt(receipt, verifier)) throw new TelemetryTransportException("The receiver returned an invalid settlement signature.", false);
        var proof = receipt.Content;
        var content = block.Content;
        if (proof.NodeId != content.NodeId || proof.LedgerId != content.LedgerId || proof.BlockId != content.BlockId
            || proof.SequenceNumber != content.SequenceNumber || proof.BlockHash != block.BlockHash)
            throw new TelemetryTransportException("The receipt does not identify the submitted block.", false);
        return receipt;
    }
}
