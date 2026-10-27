using System.Text.Json;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing.Contracts;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class HeartbeatAgentTests
{
    [Fact]
    public async Task LostResultResponseRetriesExactSignedReportWithoutResamplingOrRefreshingLiveness()
    {
        await using var f = await AuditFixture.CreateAsync();
        var hashes = new List<string>(); int attempts = 0;
        var transport = new AuditTransportDecorator(f.Service)
        {
            OnResponse = async (r, token) =>
            {
                hashes.Add(AuditProtocol.Hash(AuditProtocol.Encode(r.Content)));
                var result = await f.Service.SubmitAsync(r, token);
                if (Interlocked.Increment(ref attempts) == 1) throw new TelemetryTransportException("Reply lost", true);
                return result;
            }
        };
        var agent = f.Agent(transport);
        await Assert.ThrowsAsync<TelemetryTransportException>(() => agent.AuditOnceAsync());
        var accepted = (await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId))!.Result;
        f.Clock.Advance(TimeSpan.FromSeconds(20));
        var received = await agent.AuditOnceAsync();
        Assert.Equal(hashes[0], hashes[1]); Assert.Equal(accepted.Signature, received.Signature);
        Assert.Equal(accepted.Content.AcceptedUtc, agent.GetHealth().LastAcceptedUtc);
        Assert.Equal(1, agent.GetHealth().CompletedAudits);
    }
    [Fact]
    public async Task ExpiredReportIsDiscardedAndNextAttemptGetsANewChallenge()
    {
        await using var f = await AuditFixture.CreateAsync();
        int attempts = 0; var ids = new List<Guid>();
        var transport = new AuditTransportDecorator(f.Service)
        {
            OnResponse = async (r, token) =>
            {
                ids.Add(r.Content.ChallengeId);
                if (Interlocked.Increment(ref attempts) == 1) f.Clock.Advance(TimeSpan.FromMinutes(2));
                return await f.Service.SubmitAsync(r, token);
            }
        };
        var agent = f.Agent(transport);
        Assert.Equal(AuditFailure.ChallengeExpired, (await Assert.ThrowsAsync<AuditRejectedException>(() => agent.AuditOnceAsync())).Failure);
        var result = await agent.AuditOnceAsync();
        Assert.NotEqual(ids[0], ids[1]); Assert.Equal(1, result.Content.AuditSequenceNumber);
    }
    [Fact]
    public async Task AgentReportsActualCacheIntegrityFailureWithoutInventingAHealthySnapshot()
    {
        await using var f = await AuditFixture.CreateAsync();
        var block = f.Ledger.First;
        var corrupted = block with { Content = block.Content with { Payload = [0, 1, 2] } };
        f.Ledger.Local.Execute("UPDATE blocks SET body=$body WHERE sequence=1", ("$body", JsonSerializer.SerializeToUtf8Bytes(corrupted)));
        var agent = f.Agent();
        var result = await agent.AuditOnceAsync();
        Assert.Contains(AuditFinding.LocalCacheIntegrityFailure, result.Content.Findings);
        var record = await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId);
        Assert.Equal(CacheAuditOutcome.IntegrityFailed, record!.Response.Content.Cache.Outcome);
        Assert.Null(record.Response.Content.Cache.Snapshot);
        Assert.Equal(ServerHealthState.Critical, (await agent.RefreshHealthAsync()).Content.Assessment.State);
    }
    [Theory]
    [InlineData("signature")]
    [InlineData("request")]
    public async Task AgentRejectsUntrustedOrMismatchedServerChallengesBeforeAuditing(string changed)
    {
        await using var f = await AuditFixture.CreateAsync();
        var transport = new AuditTransportDecorator(f.Service)
        {
            OnChallenge = async (request, token) =>
            {
                var c = await f.Service.CreateChallengeAsync(request, token);
                if (changed == "signature") { c.Signature[0] ^= 1; return c; }
                var content = c.Content with { RequestHash = new string('A', 64) };
                return new(content, f.Ledger.Local.Server.Sign(AuditProtocol.Encode(content)));
            }
        };
        Assert.False((await Assert.ThrowsAsync<TelemetryTransportException>(() => f.Agent(transport).AuditOnceAsync())).IsTransient);
        Assert.Null(await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId));
    }
    [Fact]
    public async Task AgentRejectsAValidServerSignatureForAnotherResponse()
    {
        await using var f = await AuditFixture.CreateAsync();
        var transport = new AuditTransportDecorator(f.Service)
        {
            OnResponse = async (response, token) =>
            {
                var result = await f.Service.SubmitAsync(response, token);
                var c = result.Content with { ResponseHash = new string('A', 64) };
                return new(c, f.Ledger.Local.Server.Sign(AuditProtocol.Encode(c)));
            }
        };
        var agent = f.Agent(transport);
        Assert.False((await Assert.ThrowsAsync<TelemetryTransportException>(() => agent.AuditOnceAsync())).IsTransient);
        Assert.Equal(0, agent.GetHealth().CompletedAudits);
    }
    [Fact]
    public async Task TemporaryHealthReadFailureRetriesTheReadWithoutMintingAnotherAudit()
    {
        await using var f = await AuditFixture.CreateAsync(); int reads = 0;
        var transport = new AuditTransportDecorator(f.Service)
        {
            OnHealth = (query, token) => Interlocked.Increment(ref reads) == 1
                ? Task.FromException<SignedNodeHealth>(new TelemetryTransportException("temporary read failure", true))
                : f.Service.GetHealthAsync(query, token)
        };
        var agent = f.Agent(transport, options: new() { Interval = TimeSpan.FromHours(1), InitialRetryDelay = TimeSpan.FromMilliseconds(5), MaximumRetryDelay = TimeSpan.FromMilliseconds(10) });
        using var stop = new CancellationTokenSource(); var run = agent.RunAsync(stop.Token);
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (agent.GetHealth().LastHealth is null) await Task.Delay(10, deadline.Token);
        }
        finally { await stop.CancelAsync(); await run; }
        Assert.Equal(1, agent.GetHealth().CompletedAudits); Assert.Equal(1, agent.GetHealth().TransientFailures);
        Assert.Equal(1, (await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId))!.Result.Content.AuditSequenceNumber);
    }
    [Fact]
    public async Task UnavailableCacheProducesAnAuthenticatedAvailabilityFinding()
    {
        await using var f = await AuditFixture.CreateAsync(); await f.Ledger.Cache.DisposeAsync();
        var agent = f.Agent(); var result = await agent.AuditOnceAsync();
        Assert.Contains(AuditFinding.CacheAuditUnavailable, result.Content.Findings);
        Assert.DoesNotContain(AuditFinding.LocalCacheIntegrityFailure, result.Content.Findings);
        Assert.Equal(ServerHealthState.Degraded, (await agent.RefreshHealthAsync()).Content.Assessment.State);
    }
    [Fact]
    public async Task CacheAuditSnapshotCountsComeFromTheVerifiedSnapshot()
    {
        await using var f = await AuditFixture.CreateAsync();
        var second = await f.Ledger.Cache.AppendAsync([TestLedger.Event()]);
        var snapshot = await f.Ledger.Cache.CaptureAuditSnapshotAsync(new(f.NodeId, f.LedgerId, 1, f.Ledger.First.BlockHash));
        Assert.Equal(2, snapshot.Checkpoint.SequenceNumber); Assert.Equal(2, snapshot.PendingBlocks);
        Assert.Equal(f.Ledger.First.Content.Payload.Length + second.Content.Payload.Length, snapshot.StoredPayloadBytes);
        await f.Ledger.Cache.ReconcileAsync(f.Ledger.Local.Receipt(f.Ledger.First));
        var updated = await f.Ledger.Cache.CaptureAuditSnapshotAsync();
        Assert.Equal(1, updated.PendingBlocks); Assert.Equal(second.Content.Payload.Length, updated.PendingPayloadBytes);
        Assert.Equal(snapshot.StoredPayloadBytes, updated.StoredPayloadBytes);
    }
}
