using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing;
using Mrbr.Bastion.Auditing.Contracts;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class HeartbeatAuditTests
{
    [Fact]
    public async Task FreshAuditIsSignedAnchoredAndDoesNotSettleTelemetry()
    {
        await using var f = await AuditFixture.CreateAsync();
        var request = f.Request();
        var challenge = await f.Service.CreateChallengeAsync(request);
        Assert.Equal(32, challenge.Content.Nonce.Length);
        Assert.Equal(f.Ledger.First.BlockHash, challenge.Content.Anchor.BlockHash);
        Assert.True(AuditProtocol.Verify(challenge, f.Ledger.Local.Server));
        var response = await f.ResponseAsync(challenge);
        var result = await f.Service.SubmitAsync(response);
        Assert.True(AuditProtocol.Verify(result, f.Ledger.Local.Server));
        Assert.Equal(1, result.Content.AuditSequenceNumber);
        Assert.Empty(result.Content.Findings);
        var health = await f.Service.GetHealthAsync(f.Query());
        Assert.True(AuditProtocol.Verify(health, f.Ledger.Local.Server));
        Assert.Equal(ServerHealthState.Healthy, health.Content.Assessment.State);
        Assert.Equal(100, health.Content.Assessment.Score);
        Assert.Single(await f.Ledger.Cache.ReadPendingAsync());
    }
    [Fact]
    public async Task UnobservedNodeStartsUnknownRatherThanHealthy()
    {
        await using var f = await AuditFixture.CreateAsync();
        var health = await f.Service.GetHealthAsync(f.Query());
        Assert.Equal(ServerHealthState.Unknown, health.Content.Assessment.State);
        Assert.Null(health.Content.Assessment.Score);
        Assert.Null(health.Content.LastAcceptedAuditUtc);
        Assert.Contains(AuditFinding.NoHeartbeat, health.Content.Assessment.Findings);
    }
    [Fact]
    public async Task SignedRequestRetryDoesNotExtendOrReplaceTheNonce()
    {
        await using var f = await AuditFixture.CreateAsync();
        var request = f.Request();
        var first = await f.Service.CreateChallengeAsync(request);
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        var repeat = await f.Service.CreateChallengeAsync(request);
        Assert.Equal(first.Content.ChallengeId, repeat.Content.ChallengeId);
        Assert.Equal(first.Content.ExpiresUtc, repeat.Content.ExpiresUtc);
        Assert.Equal(first.Signature, repeat.Signature);
        var fresh = await f.Service.CreateChallengeAsync(f.Request());
        Assert.NotEqual(first.Content.Nonce, fresh.Content.Nonce);
    }
    [Fact]
    public async Task AnotherRequestCannotInvalidateAnOutstandingChallenge()
    {
        await using var f = await AuditFixture.CreateAsync();
        var request = f.Request(); var challenge = await f.Service.CreateChallengeAsync(request);
        Assert.Equal(AuditFailure.ChallengeOutstanding, (await Assert.ThrowsAsync<AuditRejectedException>(() => f.Service.CreateChallengeAsync(f.Request()))).Failure);
        var conflicting = f.Sign(request.Content with { CollectorRunId = Guid.NewGuid() });
        Assert.Equal(AuditFailure.ResponseConflict, (await Assert.ThrowsAsync<AuditRejectedException>(() => f.Service.CreateChallengeAsync(conflicting))).Failure);
        await f.Service.SubmitAsync(await f.ResponseAsync(challenge));
    }
    [Fact]
    public async Task InvalidSignaturesCannotCreateChallengesOrChangeVerifiedHealth()
    {
        await using var f = await AuditFixture.CreateAsync();
        var (_, accepted) = await f.AuditAsync();
        var request = f.Request(); request.Signature[0] ^= 1;
        Assert.Equal(AuditFailure.UntrustedIdentity, (await Assert.ThrowsAsync<AuditRejectedException>(() => f.Service.CreateChallengeAsync(request))).Failure);
        var validChallenge = await f.Service.CreateChallengeAsync(f.Request());
        var response = await f.ResponseAsync(validChallenge); response.Signature[0] ^= 1;
        f.Clock.Advance(TimeSpan.FromSeconds(20));
        await Assert.ThrowsAsync<AuditRejectedException>(() => f.Service.SubmitAsync(response));
        var health = await f.Service.GetHealthAsync(f.Query());
        Assert.Equal(accepted.Content.AcceptedUtc, health.Content.LastAcceptedAuditUtc);
        Assert.Equal(100, health.Content.Assessment.Score);
    }
    [Theory]
    [InlineData("nonce")]
    [InlineData("run")]
    [InlineData("hash")]
    [InlineData("challenge")]
    public async Task ValidNodeSignaturesDoNotBypassChallengeBinding(string field)
    {
        await using var f = await AuditFixture.CreateAsync();
        var challenge = await f.Service.CreateChallengeAsync(f.Request());
        var good = await f.ResponseAsync(challenge);
        var c = field switch
        {
            "nonce" => good.Content with { Nonce = new byte[32] },
            "run" => good.Content with { CollectorRunId = Guid.NewGuid() },
            "hash" => good.Content with { ChallengeHash = new string('A', 64) },
            _ => good.Content with { ChallengeId = Guid.NewGuid() }
        };
        Assert.Equal(AuditFailure.ChallengeMismatch, (await Assert.ThrowsAsync<AuditRejectedException>(() => f.Service.SubmitAsync(f.Sign(c)))).Failure);
        Assert.Null(await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId));
        Assert.Equal(1, (await f.Service.SubmitAsync(good)).Content.AuditSequenceNumber);
    }
    [Fact]
    public async Task ExpiredChallengeCannotRefreshLivenessOrConsumeAnAssessmentSequence()
    {
        await using var f = await AuditFixture.CreateAsync();
        var c = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(c);
        f.Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(AuditFailure.ChallengeExpired, (await Assert.ThrowsAsync<AuditRejectedException>(() => f.Service.SubmitAsync(response))).Failure);
        Assert.Null(await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId));
        Assert.Equal(1, (await f.AuditAsync()).Result.Content.AuditSequenceNumber);
    }
    [Fact]
    public async Task ConcurrentIdenticalResponsesConsumeNonceOnceAndReturnIdenticalProof()
    {
        await using var f = await AuditFixture.CreateAsync();
        var c = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(c);
        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => f.Service.SubmitAsync(response))));
        Assert.All(results, r => Assert.Equal(results[0].Signature, r.Signature));
        Assert.All(results, r => Assert.Equal(1, r.Content.AuditSequenceNumber));
        await f.Store.VerifyIntegrityAsync();
    }
    [Fact]
    public async Task ConsumedNonceRejectsDifferentSignedContent()
    {
        await using var f = await AuditFixture.CreateAsync();
        var (response, original) = await f.AuditAsync();
        var changed = f.Sign(response.Content with { Collector = response.Content.Collector with { State = MonitorState.Faulted } });
        Assert.Equal(AuditFailure.ResponseConflict, (await Assert.ThrowsAsync<AuditRejectedException>(() => f.Service.SubmitAsync(changed))).Failure);
        Assert.Equal(original.Signature, (await f.Service.SubmitAsync(response)).Signature);
    }
    [Fact]
    public async Task RestartedReceiverReturnsStoredAssessmentAndReplayDoesNotPreventOfflineStatus()
    {
        await using var f = await AuditFixture.CreateAsync();
        var (response, accepted) = await f.AuditAsync();
        f.Clock.Advance(TimeSpan.FromMinutes(6));
        await f.ReopenAsync();
        var repeat = await f.Service.SubmitAsync(response);
        Assert.Equal(accepted.Signature, repeat.Signature);
        var health = await f.Service.GetHealthAsync(f.Query());
        Assert.Equal(accepted.Content.AcceptedUtc, health.Content.LastAcceptedAuditUtc);
        Assert.Equal(ServerHealthState.Offline, health.Content.Assessment.State);
        Assert.Equal(0, health.Content.Assessment.Score);
    }
    [Fact]
    public async Task LocalBacklogAheadOfKnownAnchorIsNotRollbackOrASequenceFailure()
    {
        await using var f = await AuditFixture.CreateAsync();
        await f.Ledger.Cache.AppendAsync([TestLedger.Event()]);
        var (_, result) = await f.AuditAsync();
        Assert.Contains(AuditFinding.LocalTailAwaitingIngestion, result.Content.Findings);
        Assert.DoesNotContain(AuditFinding.LocalLedgerRollback, result.Content.Findings);
        Assert.Equal(100, (await f.Service.GetHealthAsync(f.Query())).Content.Assessment.Score);
    }
    [Fact]
    public async Task LaterIngestionCorroboratesTheTailWithoutRefreshingHeartbeatTime()
    {
        await using var f = await AuditFixture.CreateAsync();
        var second = await f.Ledger.Cache.AppendAsync([TestLedger.Event()]);
        var (_, accepted) = await f.AuditAsync();
        Assert.Contains(AuditFinding.LocalTailAwaitingIngestion, accepted.Content.Findings);
        await f.Ledger.Service.IngestAsync(second); f.Clock.Advance(TimeSpan.FromSeconds(10));
        var health = await f.Service.GetHealthAsync(f.Query());
        Assert.DoesNotContain(AuditFinding.LocalTailAwaitingIngestion, health.Content.Assessment.Findings);
        Assert.Equal(accepted.Content.AcceptedUtc, health.Content.LastAcceptedAuditUtc);
        Assert.Equal(AuditProtocol.Hash(AuditProtocol.Encode(accepted.Content)), health.Content.LastResultHash);
    }
    [Fact]
    public async Task LaterIngestionExposesAConflictingPreviouslyUnconfirmedTail()
    {
        await using var f = await AuditFixture.CreateAsync();
        var second = await f.Ledger.Cache.AppendAsync([TestLedger.Event()]);
        var challenge = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(challenge);
        var snapshot = response.Content.Cache.Snapshot!;
        var claimed = f.Sign(response.Content with { Cache = response.Content.Cache with { Snapshot = snapshot with
        { Checkpoint = snapshot.Checkpoint with { BlockHash = new string('A', 64) } } } });
        var accepted = await f.Service.SubmitAsync(claimed);
        Assert.DoesNotContain(AuditFinding.CheckpointHashMismatch, accepted.Content.Findings);
        await f.Ledger.Service.IngestAsync(second);
        var health = await f.Service.GetHealthAsync(f.Query());
        Assert.Contains(AuditFinding.CheckpointHashMismatch, health.Content.Assessment.Findings);
        Assert.Equal(ServerHealthState.Critical, health.Content.Assessment.State);
        Assert.Equal(accepted.Content.AcceptedUtc, health.Content.LastAcceptedAuditUtc);
    }
    [Fact]
    public async Task IngestionAdvancingDuringAnAuditDoesNotCreateFalseRollback()
    {
        await using var f = await AuditFixture.CreateAsync();
        var c = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(c);
        var second = await f.Ledger.Cache.AppendAsync([TestLedger.Event()]); await f.Ledger.Service.IngestAsync(second);
        var result = await f.Service.SubmitAsync(response);
        Assert.DoesNotContain(AuditFinding.LocalLedgerRollback, result.Content.Findings);
    }
    [Fact]
    public async Task SignedHashMismatchAndRollbackAreReconciledAgainstReceiverAnchor()
    {
        await using var f = await AuditFixture.CreateAsync();
        var c = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(c);
        var status = response.Content.Cache.Snapshot!;
        var bad = f.Sign(response.Content with { Cache = response.Content.Cache with { Snapshot = status with
        { Checkpoint = status.Checkpoint with { BlockHash = new string('A', 64) } } } });
        var result = await f.Service.SubmitAsync(bad);
        Assert.Contains(AuditFinding.CheckpointHashMismatch, result.Content.Findings);
        Assert.Equal(ServerHealthState.Critical, (await f.Service.GetHealthAsync(f.Query())).Content.Assessment.State);
    }
    [Fact]
    public async Task AValidlySignedLowerLocalSequenceIsFlaggedAgainstKnownReceiverEvidence()
    {
        await using var f = await AuditFixture.CreateAsync();
        var c = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(c);
        var lower = f.Sign(response.Content with { Cache = response.Content.Cache with
        { Snapshot = new CacheStatus(new(f.NodeId, f.LedgerId, 0, AuditProtocol.GenesisHash), 0, 0, 0) } });
        var result = await f.Service.SubmitAsync(lower);
        Assert.Contains(AuditFinding.LocalLedgerRollback, result.Content.Findings);
        Assert.Equal(20, (await f.Service.GetHealthAsync(f.Query())).Content.Assessment.Score);
    }
    [Fact]
    public async Task ClockSkewIsReportedWithoutUsingTheClientClockForNonceFreshness()
    {
        await using var f = await AuditFixture.CreateAsync();
        var c = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(c);
        var skewed = f.Sign(response.Content with { SampledUtc = response.Content.SampledUtc.AddMinutes(2) });
        Assert.Contains(AuditFinding.ClockSkewOrDelay, (await f.Service.SubmitAsync(skewed)).Content.Findings);
        Assert.Equal(85, (await f.Service.GetHealthAsync(f.Query())).Content.Assessment.Score);
    }
    [Fact]
    public async Task EventLossDeductionsUseNewDeltasAndCollectorRestartsResetBaselines()
    {
        await using var f = await AuditFixture.CreateAsync();
        f.Metrics = f.Metrics with { ReceivedEvents = 100, PersistedEvents = 90, QueueDroppedEvents = 5, SourceLostEvents = 2, UnpersistedEvents = 5 };
        var (_, first) = await f.AuditAsync();
        Assert.Equal(5, first.Content.NewQueueDroppedEvents); Assert.Equal(2, first.Content.NewSourceLostEvents);
        Assert.Equal(75, (await f.Service.GetHealthAsync(f.Query())).Content.Assessment.Score);
        f.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.DoesNotContain(AuditFinding.EventsLost, (await f.AuditAsync()).Result.Content.Findings);
        f.RunId = Guid.NewGuid(); f.Metrics = f.Metrics with { QueueDroppedEvents = 0, SourceLostEvents = 0, ReceivedEvents = 0, PersistedEvents = 0 };
        var (_, restarted) = await f.AuditAsync();
        Assert.Contains(AuditFinding.CollectorRestarted, restarted.Content.Findings);
        Assert.DoesNotContain(AuditFinding.CounterRollback, restarted.Content.Findings);
    }
    [Fact]
    public async Task DecreasingCountersInSameRunAreFlagged()
    {
        await using var f = await AuditFixture.CreateAsync();
        f.Metrics = f.Metrics with { ReceivedEvents = 20 }; await f.AuditAsync();
        f.Metrics = f.Metrics with { ReceivedEvents = 1 };
        Assert.Contains(AuditFinding.CounterRollback, (await f.AuditAsync()).Result.Content.Findings);
    }
    [Fact]
    public async Task SigningFailureDoesNotConsumeNonceOrRefreshHealth()
    {
        await using var f = await AuditFixture.CreateAsync();
        var request = f.Request(); var challenge = await f.Service.CreateChallengeAsync(request); var response = await f.ResponseAsync(challenge);
        var signer = new FailingSigner(f.Ledger.Local.Server) { ShouldFail = true };
        var service = new HeartbeatAuditService(f.Ledger.Trust, f.Ledger.Store, f.Store, signer, f.Ledger.Local.Server, timeProvider: f.Clock);
        await Assert.ThrowsAsync<IOException>(() => service.SubmitAsync(response));
        Assert.Null(await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId));
        signer.ShouldFail = false;
        Assert.Equal(1, (await service.SubmitAsync(response)).Content.AuditSequenceNumber);
    }
    [Fact]
    public async Task ReadQueriesCannotRefreshFreshnessAndServerClockRollbackIsUnknown()
    {
        await using var f = await AuditFixture.CreateAsync();
        var (_, accepted) = await f.AuditAsync();
        f.Clock.Advance(TimeSpan.FromSeconds(90));
        var stale = await f.Service.GetHealthAsync(f.Query());
        Assert.Equal(ServerHealthState.Degraded, stale.Content.Assessment.State);
        Assert.Contains(AuditFinding.StaleHeartbeat, stale.Content.Assessment.Findings);
        Assert.Equal(accepted.Content.AcceptedUtc, stale.Content.LastAcceptedAuditUtc);
        f.Clock.SetUtc(accepted.Content.AcceptedUtc.AddSeconds(-1));
        var unknown = await f.Service.GetHealthAsync(f.Query());
        Assert.Equal(ServerHealthState.Unknown, unknown.Content.Assessment.State); Assert.Null(unknown.Content.Assessment.Score);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Service.CreateChallengeAsync(f.Request()));
    }
}
