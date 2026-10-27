using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Auditing.Contracts;

public sealed record AuditRequestContent(int Version, string NodeId, Guid LedgerId, Guid RequestId,
    Guid CollectorRunId, DateTimeOffset RequestedUtc, string Algorithm, string KeyId);
public sealed record SignedAuditRequest(AuditRequestContent Content, byte[] Signature);

public sealed record AuditChallengeContent(int Version, string NodeId, Guid LedgerId, Guid RequestId,
    Guid CollectorRunId, Guid ChallengeId, string RequestHash, byte[] Nonce,
    DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc, LedgerCheckpoint Anchor, string Algorithm, string KeyId);
public sealed record SignedAuditChallenge(AuditChallengeContent Content, byte[] Signature);

public enum CacheAuditOutcome { Verified, IntegrityFailed, Unavailable }
public sealed record CollectorMetrics(MonitorState State, long ReceivedEvents, long FilteredEvents,
    long QueueDroppedEvents, long SourceLostEvents, long PersistedEvents, long PersistedBlocks, long UnpersistedEvents)
{
    public static CollectorMetrics FromHealth(MonitorHealth health) => new(health.State, health.ReceivedEvents,
        health.FilteredEvents, health.QueueDroppedEvents, health.SourceLostEvents, health.PersistedEvents,
        health.PersistedBlocks, health.UnpersistedEvents);
}
public sealed record CacheAuditObservation(CacheAuditOutcome Outcome, DateTimeOffset CheckedUtc, CacheStatus? Snapshot);
public sealed record AuditResponseContent(int Version, string NodeId, Guid LedgerId, Guid CollectorRunId,
    Guid ChallengeId, string ChallengeHash, byte[] Nonce, DateTimeOffset SampledUtc, long CollectorUptimeMilliseconds,
    CollectorMetrics Collector, CacheAuditObservation Cache, string Algorithm, string KeyId);
public sealed record SignedAuditResponse(AuditResponseContent Content, byte[] Signature);

// Findings describe authenticated observations and reconciliation results, not proof of an intrusion.
public enum AuditFinding
{
    LocalCacheIntegrityFailure = 1, CacheAuditUnavailable, LocalLedgerRollback, CheckpointHashMismatch,
    CollectorFaulted, CollectorStopped, CollectorNotStarted, CounterRollback, EventsLost,
    ClockSkewOrDelay, LargeBacklog, CollectorRestarted, LocalTailAwaitingIngestion,
    StaleHeartbeat, Offline, NoHeartbeat, ServerClockInconsistent
}
public sealed record AuditVerificationPolicy(string Version, long ClockSkewWarningMilliseconds, long BacklogWarningBlocks, long BacklogWarningBytes);
public sealed record AuditResultContent(int Version, string NodeId, Guid LedgerId, Guid CollectorRunId,
    Guid ChallengeId, string ChallengeHash, string ResponseHash, long AuditSequenceNumber,
    string PreviousResultHash, DateTimeOffset AcceptedUtc, AuditFinding[] Findings,
    long NewQueueDroppedEvents, long NewSourceLostEvents, AuditVerificationPolicy Policy, string Algorithm, string KeyId);
public sealed record SignedAuditResult(AuditResultContent Content, byte[] Signature);
public sealed record AuditRecord(SignedAuditRequest Request, SignedAuditChallenge Challenge,
    SignedAuditResponse Response, SignedAuditResult Result);

public sealed record HealthQueryContent(int Version, string NodeId, Guid LedgerId, Guid QueryId,
    DateTimeOffset RequestedUtc, string Algorithm, string KeyId);
public sealed record SignedHealthQuery(HealthQueryContent Content, byte[] Signature);
public enum ServerHealthState { Unknown, Healthy, Degraded, Critical, Offline }
public sealed record HealthAssessment(string PolicyVersion, ServerHealthState State, int? Score, AuditFinding[] Findings,
    long StaleAfterMilliseconds, long OfflineAfterMilliseconds);
public sealed record NodeHealthContent(int Version, string NodeId, Guid LedgerId, string QueryHash,
    DateTimeOffset GeneratedUtc, DateTimeOffset? LastAcceptedAuditUtc, long? LastAuditSequenceNumber,
    string? LastResultHash, HealthAssessment Assessment, string Algorithm, string KeyId);
public sealed record SignedNodeHealth(NodeHealthContent Content, byte[] Signature);
public sealed record NodeHealthSnapshot(string NodeId, Guid LedgerId, DateTimeOffset GeneratedUtc,
    DateTimeOffset? LastAcceptedAuditUtc, long? LastAuditSequenceNumber, string? LastResultHash, HealthAssessment Assessment);
/// <summary>Trusted server-side read API for an application's authenticated operator/reporting adapters.</summary>
public interface INodeHealthReader
{
    Task<NodeHealthSnapshot> ReadNodeHealthAsync(string nodeId, Guid ledgerId, CancellationToken cancellationToken = default);
}

public enum AuditFailure
{
    InvalidEnvelope, UntrustedIdentity, ChallengeOutstanding, ChallengeExpired, ChallengeMismatch,
    ResponseConflict, CapacityExceeded
}
public sealed class AuditRejectedException(AuditFailure failure, string message) : Exception(message)
{
    public AuditFailure Failure { get; } = failure;
    public bool IsTransient => Failure is AuditFailure.ChallengeOutstanding or AuditFailure.CapacityExceeded;
}
public sealed record AuditError(AuditFailure Failure);
public interface IHeartbeatAuditTransport
{
    Task<SignedAuditChallenge> CreateChallengeAsync(SignedAuditRequest request, CancellationToken cancellationToken = default);
    Task<SignedAuditResult> SubmitAsync(SignedAuditResponse response, CancellationToken cancellationToken = default);
    Task<SignedNodeHealth> GetHealthAsync(SignedHealthQuery query, CancellationToken cancellationToken = default);
}
public interface IHeartbeatAuditService : IHeartbeatAuditTransport { }
