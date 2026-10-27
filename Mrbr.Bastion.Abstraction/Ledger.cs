namespace Mrbr.Bastion.Abstraction;

/// <summary>Immutable block metadata and serialized telemetry, all covered by the block hash and signature.</summary>
public sealed record TelemetryBlockContent(
    int Version,
    string NodeId,
    Guid LedgerId,
    Guid BlockId,
    long SequenceNumber,
    DateTimeOffset CreatedUtc,
    string PreviousBlockHash,
    string PayloadFormat,
    int EventCount,
    string Algorithm,
    string KeyId,
    byte[] Payload);

/// <summary>A verifiable block. Byte arrays are owned by the caller and must not be mutated during use.</summary>
public sealed record SignedTelemetryBlock(TelemetryBlockContent Content, string BlockHash, byte[] Signature);

/// <summary>A receiver's assertion that this exact block has been durably committed.</summary>
public sealed record SettlementReceiptContent(
    int Version,
    string NodeId,
    Guid LedgerId,
    Guid BlockId,
    long SequenceNumber,
    string BlockHash,
    DateTimeOffset AcceptedUtc,
    string Algorithm,
    string KeyId);

/// <summary>A signed durable-commit receipt. An HTTP success status alone is not a receipt.</summary>
public sealed record SettlementReceipt(SettlementReceiptContent Content, byte[] Signature);

/// <summary>A chain anchor. Store it externally if suffix truncation or whole-file rollback must be detected.</summary>
public sealed record LedgerCheckpoint(string NodeId, Guid LedgerId, long SequenceNumber, string BlockHash);

/// <summary>Persisted cache state, including unsettled data.</summary>
public sealed record CacheStatus(LedgerCheckpoint Checkpoint, long PendingBlocks, long PendingPayloadBytes, long StoredPayloadBytes);

/// <summary>A durable outbox. A successful append acknowledges local commit, not complete source capture.</summary>
public interface ITelemetryCache : IAsyncDisposable
{
    /// <summary>Atomically appends one signed block and advances the persisted sequence and chain tip.</summary>
    Task<SignedTelemetryBlock> AppendAsync(IReadOnlyList<TelemetryEvent> events, CancellationToken cancellationToken = default);
    /// <summary>Returns verified pending blocks in sequence order. Reading does not mark them delivered.</summary>
    Task<IReadOnlyList<SignedTelemetryBlock>> ReadPendingAsync(int maximumBlocks = 100, CancellationToken cancellationToken = default);
    /// <summary>Verifies the server signature and exact block identity, then durably settles it. Retries are idempotent.</summary>
    Task ReconcileAsync(SettlementReceipt receipt, CancellationToken cancellationToken = default);
    /// <summary>Verifies all retained blocks and receipts, optionally against a trusted external checkpoint.</summary>
    Task VerifyIntegrityAsync(LedgerCheckpoint? trustedCheckpoint = null, CancellationToken cancellationToken = default);
    /// <summary>Returns the durable chain tip and storage counts.</summary>
    Task<CacheStatus> GetStatusAsync(CancellationToken cancellationToken = default);
}

/// <summary>Captures cache audit evidence from one verified database snapshot.</summary>
public interface IAuditableTelemetryCache : ITelemetryCache
{
    /// <summary>Verifies retained evidence against an external anchor and returns status from that same snapshot.</summary>
    Task<CacheStatus> CaptureAuditSnapshotAsync(LedgerCheckpoint? trustedCheckpoint = null, CancellationToken cancellationToken = default);
}
