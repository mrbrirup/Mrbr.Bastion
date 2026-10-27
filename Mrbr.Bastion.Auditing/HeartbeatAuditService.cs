using System.Security.Cryptography;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Health;
using Mrbr.Bastion.Ingestion;

namespace Mrbr.Bastion.Auditing;

/// <summary>Verifies fresh signed observations, reconciles known ledger evidence, and signs durable assessments.</summary>
public sealed class HeartbeatAuditService : IHeartbeatAuditService, INodeHealthReader
{
    public const string VerificationPolicyVersion = "mrbr.bastion.audit-verification.v1";
    private readonly INodeTrustStore _trust;
    private readonly IIngestionStore _ledger;
    private readonly IHeartbeatAuditStore _audits;
    private readonly ISignatureSigner _signer;
    private readonly ISignatureVerifier _serverVerifier;
    private readonly IServerHealthScorer _scorer;
    private readonly HeartbeatVerificationOptions _options;
    private readonly TimeProvider _time;
    public HeartbeatAuditService(INodeTrustStore trust, IIngestionStore ledger, IHeartbeatAuditStore audits,
        ISignatureSigner signer, ISignatureVerifier serverVerifier, IServerHealthScorer? scorer = null,
        HeartbeatVerificationOptions? options = null, TimeProvider? timeProvider = null)
    {
        _trust = trust ?? throw new ArgumentNullException(nameof(trust));
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        _audits = audits ?? throw new ArgumentNullException(nameof(audits));
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _serverVerifier = serverVerifier ?? throw new ArgumentNullException(nameof(serverVerifier));
        _scorer = scorer ?? new ServerHealthScorer();
        _options = options ?? new(); _options.Validate(); _time = timeProvider ?? TimeProvider.System;
    }
    public async Task<SignedAuditChallenge> CreateChallengeAsync(SignedAuditRequest request, CancellationToken cancellationToken = default)
    {
        request = AuditAuthentication.Verify(request, _trust);
        var r = request.Content;
        var previous = await _audits.ReadLatestAsync(r.NodeId, r.LedgerId, cancellationToken).ConfigureAwait(false);
        if (previous is not null) await VerifyReceiverAnchorAsync(previous.Challenge.Content.Anchor, cancellationToken).ConfigureAwait(false);
        var anchor = await _ledger.GetCheckpointAsync(r.NodeId, r.LedgerId, cancellationToken).ConfigureAwait(false)
            ?? new LedgerCheckpoint(r.NodeId, r.LedgerId, 0, AuditProtocol.GenesisHash);
        await VerifyReceiverAnchorAsync(anchor, cancellationToken).ConfigureAwait(false);
        return await _audits.GetOrCreateAsync(request, now =>
        {
            var c = new AuditChallengeContent(1, r.NodeId, r.LedgerId, r.RequestId, r.CollectorRunId, Guid.NewGuid(),
                AuditProtocol.Hash(AuditProtocol.Encode(r)), RandomNumberGenerator.GetBytes(32), now, now + _options.ChallengeLifetime,
                anchor, _signer.Algorithm, _signer.KeyId);
            var challenge = new SignedAuditChallenge(c, _signer.Sign(AuditProtocol.Encode(c)));
            if (!AuditProtocol.Verify(challenge, _serverVerifier)) throw new CryptographicException("The prepared audit challenge failed verification.");
            return challenge;
        }, cancellationToken).ConfigureAwait(false);
    }
    public async Task<SignedAuditResult> SubmitAsync(SignedAuditResponse response, CancellationToken cancellationToken = default)
    {
        response = AuditAuthentication.Verify(response, _trust);
        var r = response.Content;
        var issued = await _audits.ReadChallengeAsync(r.ChallengeId, cancellationToken).ConfigureAwait(false);
        if (issued is null) throw new AuditRejectedException(AuditFailure.ChallengeMismatch, "Unknown audit challenge.");
        try { AuditProtocol.Bind(response, issued); }
        catch (InvalidDataException) { throw new AuditRejectedException(AuditFailure.ChallengeMismatch, "The response does not match its issued challenge."); }
        await VerifyReceiverAnchorAsync(issued.Content.Anchor, cancellationToken).ConfigureAwait(false);
        // This lookup is corroborating evidence only. The challenge's issuance anchor remains authoritative for rollback checks.
        string? receivedTail = null;
        if (r.Cache.Snapshot is { Checkpoint.SequenceNumber: > 0 } cache)
            receivedTail = (await _ledger.ReadAsync(r.NodeId, r.LedgerId, cache.Checkpoint.SequenceNumber, cancellationToken).ConfigureAwait(false))?.Block.BlockHash;
        return await _audits.CompleteAsync(response, (previous, challenge, now) =>
        {
            var findings = Assess(response, previous, challenge, receivedTail, now, out long drops, out long lost);
            var content = new AuditResultContent(1, r.NodeId, r.LedgerId, r.CollectorRunId, r.ChallengeId,
                r.ChallengeHash, AuditProtocol.Hash(AuditProtocol.Encode(r)), checked((previous?.Result.Content.AuditSequenceNumber ?? 0) + 1),
                previous is null ? AuditProtocol.GenesisHash : AuditProtocol.Hash(AuditProtocol.Encode(previous.Result.Content)), now,
                findings, drops, lost, new(VerificationPolicyVersion, (long)_options.MaximumClockSkewOrDelay.TotalMilliseconds,
                    _options.BacklogWarningBlocks, _options.BacklogWarningBytes), _signer.Algorithm, _signer.KeyId);
            var result = new SignedAuditResult(content, _signer.Sign(AuditProtocol.Encode(content)));
            if (!AuditProtocol.Verify(result, _serverVerifier)) throw new CryptographicException("The prepared audit result failed verification.");
            return result;
        }, cancellationToken).ConfigureAwait(false);
    }
    public async Task<SignedNodeHealth> GetHealthAsync(SignedHealthQuery query, CancellationToken cancellationToken = default)
    {
        query = AuditAuthentication.Verify(query, _trust);
        var q = query.Content;
        var snapshot = await ReadNodeHealthAsync(q.NodeId, q.LedgerId, cancellationToken).ConfigureAwait(false);
        var c = new NodeHealthContent(1, q.NodeId, q.LedgerId, AuditProtocol.Hash(AuditProtocol.Encode(q)), snapshot.GeneratedUtc,
            snapshot.LastAcceptedAuditUtc, snapshot.LastAuditSequenceNumber, snapshot.LastResultHash,
            snapshot.Assessment, _signer.Algorithm, _signer.KeyId);
        var health = new SignedNodeHealth(c, _signer.Sign(AuditProtocol.Encode(c)));
        if (!AuditProtocol.Verify(health, _serverVerifier)) throw new CryptographicException("The prepared health projection failed verification.");
        return health;
    }
    public async Task<NodeHealthSnapshot> ReadNodeHealthAsync(string nodeId, Guid ledgerId, CancellationToken cancellationToken = default)
    {
        if (_trust.Resolve(nodeId, ledgerId) is null) throw new AuditRejectedException(AuditFailure.UntrustedIdentity, "Unknown node/ledger enrollment.");
        var latest = await _audits.ReadLatestAsync(nodeId, ledgerId, cancellationToken).ConfigureAwait(false);
        if (latest is not null) await VerifyReceiverAnchorAsync(latest.Challenge.Content.Anchor, cancellationToken).ConfigureAwait(false);
        var now = _time.GetUtcNow(); var result = latest?.Result.Content;
        var projected = result;
        if (latest?.Response.Content.Cache.Snapshot is { Checkpoint.SequenceNumber: > 0 } cache)
        {
            var tail = await _ledger.ReadAsync(nodeId, ledgerId, cache.Checkpoint.SequenceNumber, cancellationToken).ConfigureAwait(false);
            if (tail is not null)
            {
                var findings = result!.Findings.Where(f => f != AuditFinding.LocalTailAwaitingIngestion);
                if (tail.Block.BlockHash != cache.Checkpoint.BlockHash) findings = findings.Append(AuditFinding.CheckpointHashMismatch);
                projected = result with { Findings = AuditProtocol.Normalize(findings) };
            }
        }
        return new(nodeId, ledgerId, now, result?.AcceptedUtc, result?.AuditSequenceNumber,
            result is null ? null : AuditProtocol.Hash(AuditProtocol.Encode(result)), _scorer.Evaluate(projected, now));
    }
    private async Task VerifyReceiverAnchorAsync(LedgerCheckpoint anchor, CancellationToken cancellationToken)
    {
        if (anchor.SequenceNumber == 0) return;
        var committed = await _ledger.ReadAsync(anchor.NodeId, anchor.LedgerId, anchor.SequenceNumber, cancellationToken).ConfigureAwait(false);
        if (committed is null || committed.Block.BlockHash != anchor.BlockHash)
            throw new InvalidDataException("The receiver no longer retains evidence matching its signed audit anchor.");
    }
    private AuditFinding[] Assess(SignedAuditResponse response, AuditRecord? previous, SignedAuditChallenge challenge,
        string? receivedTail, DateTimeOffset now, out long dropped, out long lost)
    {
        var r = response.Content;
        var old = previous?.Response.Content;
        var findings = new List<AuditFinding>();
        if (r.Cache.Outcome == CacheAuditOutcome.IntegrityFailed) findings.Add(AuditFinding.LocalCacheIntegrityFailure);
        if (r.Cache.Outcome == CacheAuditOutcome.Unavailable) findings.Add(AuditFinding.CacheAuditUnavailable);
        if (r.Cache.Snapshot is { } cache)
        {
            var local = cache.Checkpoint; var anchor = challenge.Content.Anchor;
            if (local.SequenceNumber < anchor.SequenceNumber) findings.Add(AuditFinding.LocalLedgerRollback);
            if (local.SequenceNumber == anchor.SequenceNumber && local.BlockHash != anchor.BlockHash) findings.Add(AuditFinding.CheckpointHashMismatch);
            if (receivedTail is not null && receivedTail != local.BlockHash) findings.Add(AuditFinding.CheckpointHashMismatch);
            if (old?.Cache.Snapshot is { } oldCache && local.SequenceNumber < oldCache.Checkpoint.SequenceNumber) findings.Add(AuditFinding.LocalLedgerRollback);
            if (local.SequenceNumber > anchor.SequenceNumber && receivedTail is null) findings.Add(AuditFinding.LocalTailAwaitingIngestion);
            if (cache.PendingBlocks >= _options.BacklogWarningBlocks || cache.PendingPayloadBytes >= _options.BacklogWarningBytes) findings.Add(AuditFinding.LargeBacklog);
        }
        switch (r.Collector.State)
        {
            case MonitorState.Faulted: findings.Add(AuditFinding.CollectorFaulted); break;
            case MonitorState.Stopped: findings.Add(AuditFinding.CollectorStopped); break;
            case MonitorState.Created: findings.Add(AuditFinding.CollectorNotStarted); break;
        }
        bool sameRun = old?.CollectorRunId == r.CollectorRunId;
        if (old is not null && !sameRun) findings.Add(AuditFinding.CollectorRestarted);
        if (sameRun && (r.CollectorUptimeMilliseconds < old!.CollectorUptimeMilliseconds
            || r.Collector.ReceivedEvents < old.Collector.ReceivedEvents || r.Collector.FilteredEvents < old.Collector.FilteredEvents
            || r.Collector.PersistedEvents < old.Collector.PersistedEvents || r.Collector.PersistedBlocks < old.Collector.PersistedBlocks
            || r.Collector.QueueDroppedEvents < old.Collector.QueueDroppedEvents || r.Collector.SourceLostEvents < old.Collector.SourceLostEvents))
            findings.Add(AuditFinding.CounterRollback);
        dropped = sameRun ? Math.Max(0, r.Collector.QueueDroppedEvents - old!.Collector.QueueDroppedEvents) : r.Collector.QueueDroppedEvents;
        lost = sameRun ? Math.Max(0, r.Collector.SourceLostEvents - old!.Collector.SourceLostEvents) : r.Collector.SourceLostEvents;
        if (dropped > 0 || lost > 0) findings.Add(AuditFinding.EventsLost);
        if ((now - r.SampledUtc).Duration() > _options.MaximumClockSkewOrDelay
            || (r.SampledUtc - r.Cache.CheckedUtc).Duration() > _options.MaximumClockSkewOrDelay) findings.Add(AuditFinding.ClockSkewOrDelay);
        return AuditProtocol.Normalize(findings);
    }
}
