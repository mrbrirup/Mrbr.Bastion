using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Ingestion;

public interface ITelemetryIngestor
{
    Task<SettlementReceipt> IngestAsync(SignedTelemetryBlock block, CancellationToken cancellationToken = default);
}
public interface INodeTrustStore
{
    /// <summary>Resolve only explicitly enrolled node/ledger pairs. Untrusted IDs must not initiate external lookups.</summary>
    ISignatureVerifier? Resolve(string nodeId, Guid ledgerId);
}
public sealed record NodeEnrollment(string NodeId, Guid LedgerId, ISignatureVerifier Verifier);
public sealed class StaticNodeTrustStore : INodeTrustStore
{
    private readonly Dictionary<(string Node, Guid Ledger), ISignatureVerifier> _nodes = new();
    public StaticNodeTrustStore(IEnumerable<NodeEnrollment> enrollments)
    {
        ArgumentNullException.ThrowIfNull(enrollments);
        foreach (var item in enrollments)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(item.NodeId);
            ArgumentNullException.ThrowIfNull(item.Verifier);
            if (item.NodeId.Length > 256 || item.LedgerId == Guid.Empty || !_nodes.TryAdd((item.NodeId, item.LedgerId), item.Verifier))
                throw new ArgumentException("Invalid or duplicate node/ledger enrollment.", nameof(enrollments));
        }
        if (_nodes.Count == 0) throw new ArgumentException("At least one node/ledger must be enrolled.", nameof(enrollments));
    }
    public ISignatureVerifier? Resolve(string nodeId, Guid ledgerId) =>
        nodeId is not null && _nodes.TryGetValue((nodeId, ledgerId), out var verifier) ? verifier : null;
}
public enum IngestionFailure { InvalidBlock, UntrustedBlock, TooLarge, SequenceConflict, ChainConflict, CapacityExceeded }
public sealed class TelemetryRejectedException(IngestionFailure failure, string message) : Exception(message)
{
    public IngestionFailure Failure { get; } = failure;
}
public sealed record IngestionOptions
{
    public IBlockPayloadCodec[] AdditionalPayloadCodecs { get; init; } = [];
    public int MaximumPayloadBytes { get; init; } = 4 * 1024 * 1024;
    public int MaximumEventsPerBlock { get; init; } = 1000;
    public void Validate()
    {
        if (MaximumPayloadBytes is < 1 or > 4 * 1024 * 1024 || MaximumEventsPerBlock is < 1 or > 10000)
            throw new ArgumentOutOfRangeException(nameof(IngestionOptions));
    }
}
public sealed record IngestedBlock(SignedTelemetryBlock Block, SettlementReceipt Receipt);
public interface IIngestionStore : IAsyncDisposable
{
    /// <summary>Accepts a verified snapshot, enforces chain order, and atomically commits block, receipt and tip.
    /// Calls the factory only for a new block. Returns only after durable commit; exact duplicates return stored proof.</summary>
    Task<SettlementReceipt> CommitAsync(SignedTelemetryBlock verifiedBlock, Func<SettlementReceipt> receiptFactory, CancellationToken cancellationToken = default);
    Task<IngestedBlock?> ReadAsync(string nodeId, Guid ledgerId, long sequenceNumber, CancellationToken cancellationToken = default);
    Task<LedgerCheckpoint?> GetCheckpointAsync(string nodeId, Guid ledgerId, CancellationToken cancellationToken = default);
    Task VerifyIntegrityAsync(CancellationToken cancellationToken = default);
}
