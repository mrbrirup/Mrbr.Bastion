using Mrbr.Bastion.Auditing.Contracts;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class AuditProtocolTests
{
    [Theory]
    [InlineData("nonce")]
    [InlineData("checkpoint")]
    [InlineData("collector")]
    [InlineData("uptime")]
    [InlineData("time")]
    [InlineData("cache-outcome")]
    [InlineData("key")]
    public async Task ResponseSignatureBindsEverySecurityRelevantObservation(string field)
    {
        await using var f = await AuditFixture.CreateAsync();
        var c = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(c);
        var original = response.Content;
        var changed = field switch
        {
            "nonce" => original with { Nonce = new byte[32] },
            "checkpoint" => original with { Cache = original.Cache with { Snapshot = original.Cache.Snapshot! with
                { Checkpoint = original.Cache.Snapshot!.Checkpoint with { BlockHash = new string('A', 64) } } } },
            "collector" => original with { Collector = original.Collector with { QueueDroppedEvents = 5 } },
            "uptime" => original with { CollectorUptimeMilliseconds = 0 },
            "time" => original with { SampledUtc = original.SampledUtc.AddSeconds(1) },
            "key" => original with { KeyId = "unknown" },
            _ => original with { Cache = original.Cache with { Outcome = CacheAuditOutcome.Unavailable, Snapshot = null } }
        };
        Assert.False(AuditProtocol.Verify(response with { Content = changed }, f.Ledger.Local.Node));
    }
    [Fact]
    public async Task ClientCannotModifyTheSignedHealthScoreOrSwapQueryIdentity()
    {
        await using var f = await AuditFixture.CreateAsync(); await f.AuditAsync();
        var query = f.Query(); var health = await f.Service.GetHealthAsync(query);
        Assert.False(AuditProtocol.Verify(health with { Content = health.Content with
            { Assessment = health.Content.Assessment with { Score = 0 } } }, f.Ledger.Local.Server));
        Assert.False(AuditProtocol.Verify(health with { Content = health.Content with
            { Assessment = health.Content.Assessment with { StaleAfterMilliseconds = 1 } } }, f.Ledger.Local.Server));
        Assert.Throws<InvalidDataException>(() => AuditProtocol.Bind(health, f.Query()));
    }
    [Fact]
    public async Task MalformedModelsAndNonCanonicalFindingListsFailClosed()
    {
        await using var f = await AuditFixture.CreateAsync(); var (_, result) = await f.AuditAsync();
        Assert.False(AuditProtocol.Verify(result with { Content = result.Content with
            { Policy = result.Content.Policy with { BacklogWarningBlocks = 1 } } }, f.Ledger.Local.Server));
        Assert.False(AuditProtocol.Verify(new SignedAuditResponse(null!, [1]), f.Ledger.Local.Node));
        Assert.Throws<InvalidDataException>(() => AuditProtocol.Encode(result.Content with { Findings = [AuditFinding.EventsLost, AuditFinding.EventsLost] }));
        Assert.Throws<InvalidDataException>(() => AuditProtocol.Encode(f.Request().Content with { NodeId = "\ud800" }));
    }
}
