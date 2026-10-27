using Mrbr.Bastion.Auditing.Contracts;

namespace Mrbr.Bastion.Auditing;

public interface IHeartbeatAuditStore : IAsyncDisposable
{
    /// <summary>Durably deduplicates signed requests and admits at most one unexpired outstanding challenge per node/ledger.</summary>
    Task<SignedAuditChallenge> GetOrCreateAsync(SignedAuditRequest request,
        Func<DateTimeOffset, SignedAuditChallenge> factory, CancellationToken cancellationToken = default);
    /// <summary>Consumes a matching nonce and commits the signed assessment atomically. Exact retries return stored results without refreshing liveness.</summary>
    Task<SignedAuditResult> CompleteAsync(SignedAuditResponse response,
        Func<AuditRecord?, SignedAuditChallenge, DateTimeOffset, SignedAuditResult> evaluate, CancellationToken cancellationToken = default);
    Task<AuditRecord?> ReadLatestAsync(string nodeId, Guid ledgerId, CancellationToken cancellationToken = default);
    Task<SignedAuditChallenge?> ReadChallengeAsync(Guid challengeId, CancellationToken cancellationToken = default);
    Task VerifyIntegrityAsync(CancellationToken cancellationToken = default);
}
public sealed record HeartbeatVerificationOptions
{
    public TimeSpan ChallengeLifetime { get; init; } = TimeSpan.FromMinutes(1);
    public TimeSpan MaximumClockSkewOrDelay { get; init; } = TimeSpan.FromSeconds(30);
    public long BacklogWarningBlocks { get; init; } = 1000;
    public long BacklogWarningBytes { get; init; } = 128L * 1024 * 1024;
    public void Validate()
    {
        if (ChallengeLifetime <= TimeSpan.Zero || ChallengeLifetime > TimeSpan.FromMinutes(10)
            || MaximumClockSkewOrDelay < TimeSpan.Zero || BacklogWarningBlocks < 1 || BacklogWarningBytes < 1)
            throw new ArgumentOutOfRangeException(nameof(HeartbeatVerificationOptions));
    }
}
