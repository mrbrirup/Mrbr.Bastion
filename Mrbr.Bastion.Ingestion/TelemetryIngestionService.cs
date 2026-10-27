using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Ingestion;

/// <summary>Transport-independent verification and receipt issuance. Supplied providers and store are caller-owned.</summary>
public sealed class TelemetryIngestionService : ITelemetryIngestor
{
    private readonly INodeTrustStore _trust;
    private readonly IIngestionStore _store;
    private readonly ISignatureSigner _signer;
    private readonly ISignatureVerifier _receiptVerifier;
    private readonly IngestionOptions _options;
    public TelemetryIngestionService(INodeTrustStore trust, IIngestionStore store, ISignatureSigner receiptSigner,
        ISignatureVerifier receiptVerifier, IngestionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(receiptSigner);
        ArgumentNullException.ThrowIfNull(receiptVerifier);
        _trust = trust;
        _store = store;
        _signer = receiptSigner;
        _receiptVerifier = receiptVerifier;
        _options = options ?? new();
        _options.Validate();
    }
    public Task<SettlementReceipt> IngestAsync(SignedTelemetryBlock block, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var verified = IngestionValidation.VerifyAndCopy(block, _trust, _options);
        return _store.CommitAsync(verified, () =>
        {
            var c = verified.Content;
            var content = new SettlementReceiptContent(LedgerProtocol.Version, c.NodeId, c.LedgerId, c.BlockId,
                c.SequenceNumber, verified.BlockHash, DateTimeOffset.UtcNow, _signer.Algorithm, _signer.KeyId);
            var receipt = new SettlementReceipt(content, _signer.Sign(LedgerProtocol.EncodeReceipt(content)));
            IngestionValidation.VerifyReceipt(receipt, verified, _receiptVerifier);
            return receipt;
        }, cancellationToken);
    }
}
