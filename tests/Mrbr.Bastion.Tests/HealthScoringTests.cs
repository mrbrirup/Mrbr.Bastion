using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Health;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class HealthScoringTests
{
    [Theory]
    [InlineData(AuditFinding.LocalCacheIntegrityFailure, 30, ServerHealthState.Critical)]
    [InlineData(AuditFinding.LocalLedgerRollback, 20, ServerHealthState.Critical)]
    [InlineData(AuditFinding.CheckpointHashMismatch, 20, ServerHealthState.Critical)]
    [InlineData(AuditFinding.ClockSkewOrDelay, 85, ServerHealthState.Degraded)]
    [InlineData(AuditFinding.EventsLost, 75, ServerHealthState.Degraded)]
    [InlineData(AuditFinding.CollectorRestarted, 100, ServerHealthState.Healthy)]
    [InlineData(AuditFinding.LocalTailAwaitingIngestion, 100, ServerHealthState.Healthy)]
    public async Task ScoreExplainsEachFindingWithoutEquatingOperationalProblemsToIntrusion(AuditFinding finding, int score, ServerHealthState state)
    {
        await using var f = await AuditFixture.CreateAsync();
        var (_, result) = await f.AuditAsync();
        var assessment = new ServerHealthScorer().Evaluate(result.Content with { Findings = [finding] }, f.Clock.GetUtcNow());
        Assert.Equal(score, assessment.Score); Assert.Equal(state, assessment.State); Assert.Contains(finding, assessment.Findings);
    }
    [Fact]
    public async Task DistinctPenaltiesAreClampedAndAgeIsCalculatedAtReadTime()
    {
        await using var f = await AuditFixture.CreateAsync();
        var (_, result) = await f.AuditAsync(); var scorer = new ServerHealthScorer();
        var severe = result.Content with { Findings = [AuditFinding.LocalLedgerRollback, AuditFinding.LocalCacheIntegrityFailure] };
        Assert.Equal(0, scorer.Evaluate(severe, f.Clock.GetUtcNow()).Score);
        Assert.Equal(ServerHealthState.Degraded, scorer.Evaluate(result.Content, result.Content.AcceptedUtc.AddSeconds(90)).State);
        Assert.Equal(ServerHealthState.Offline, scorer.Evaluate(result.Content, result.Content.AcceptedUtc.AddMinutes(5)).State);
        Assert.Null(scorer.Evaluate(null, f.Clock.GetUtcNow()).Score);
    }
}
