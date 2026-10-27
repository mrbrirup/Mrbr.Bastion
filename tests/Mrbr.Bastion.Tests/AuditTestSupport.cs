using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing;
using Mrbr.Bastion.Auditing.Agent;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Auditing.Sqlite;

namespace Mrbr.Bastion.Tests;

internal sealed class AuditClock : TimeProvider
{
    private long _utc = new DateTimeOffset(2026, 10, 26, 12, 0, 0, TimeSpan.Zero).UtcTicks;
    private long _elapsed;
    public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _utc), TimeSpan.Zero);
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => Interlocked.Read(ref _elapsed);
    public void Advance(TimeSpan time) { Interlocked.Add(ref _utc, time.Ticks); Interlocked.Add(ref _elapsed, time.Ticks); }
    public void SetUtc(DateTimeOffset time) => Interlocked.Exchange(ref _utc, time.UtcTicks);
}
internal sealed class AuditFixture : IAsyncDisposable
{
    public IngestionFixture Ledger { get; private set; } = null!;
    public AuditClock Clock { get; } = new();
    public Guid RunId { get; set; } = Guid.NewGuid();
    public MonitorHealth Metrics { get; set; } = new(MonitorState.Running, 1, 0, 0, 0, 1, 1, 0, null);
    public SqliteHeartbeatAuditStore Store { get; private set; } = null!;
    public HeartbeatAuditService Service { get; private set; } = null!;
    public string NodeId => Ledger.First.Content.NodeId;
    public Guid LedgerId => Ledger.First.Content.LedgerId;
    public SqliteAuditOptions Options => new() { DatabasePath = Path.Combine(Ledger.Local.DirectoryPath, "audits.db") };
    public static async Task<AuditFixture> CreateAsync(bool ingestFirst = true)
    {
        var f = new AuditFixture();
        try
        {
            f.Ledger = await IngestionFixture.CreateAsync();
            if (ingestFirst) await f.Ledger.Service.IngestAsync(f.Ledger.First);
            await f.ReopenAsync(); return f;
        }
        catch { await f.DisposeAsync(); throw; }
    }
    public async Task ReopenAsync(SqliteAuditOptions? options = null, ISignatureVerifier? verifier = null, ISignatureSigner? signer = null)
    {
        if (Store is not null) await Store.DisposeAsync();
        Store = await SqliteHeartbeatAuditStore.OpenAsync(options ?? Options, Ledger.Trust, verifier ?? Ledger.Local.Server, Clock);
        Service = new(Ledger.Trust, Ledger.Store, Store, signer ?? Ledger.Local.Server, verifier ?? Ledger.Local.Server, timeProvider: Clock);
    }
    public SignedAuditRequest Request()
    {
        var c = new AuditRequestContent(1, NodeId, LedgerId, Guid.NewGuid(), RunId, Clock.GetUtcNow(), Ledger.Local.Node.Algorithm, Ledger.Local.Node.KeyId);
        return Sign(c);
    }
    public SignedAuditRequest Sign(AuditRequestContent content) => new(content, Ledger.Local.Node.Sign(AuditProtocol.Encode(content)));
    public SignedAuditResponse Sign(AuditResponseContent content) => new(content, Ledger.Local.Node.Sign(AuditProtocol.Encode(content)));
    public SignedHealthQuery Query()
    {
        var c = new HealthQueryContent(1, NodeId, LedgerId, Guid.NewGuid(), Clock.GetUtcNow(), Ledger.Local.Node.Algorithm, Ledger.Local.Node.KeyId);
        return new(c, Ledger.Local.Node.Sign(AuditProtocol.Encode(c)));
    }
    public async Task<SignedAuditResponse> ResponseAsync(SignedAuditChallenge challenge)
    {
        var cache = await Ledger.Cache.CaptureAuditSnapshotAsync(challenge.Content.Anchor);
        var c = new AuditResponseContent(1, NodeId, LedgerId, RunId, challenge.Content.ChallengeId,
            AuditProtocol.Hash(AuditProtocol.Encode(challenge.Content)), challenge.Content.Nonce.ToArray(), Clock.GetUtcNow(), 1000,
            CollectorMetrics.FromHealth(Metrics), new(CacheAuditOutcome.Verified, Clock.GetUtcNow(), cache), Ledger.Local.Node.Algorithm, Ledger.Local.Node.KeyId);
        return Sign(c);
    }
    public async Task<(SignedAuditResponse Response, SignedAuditResult Result)> AuditAsync()
    {
        var challenge = await Service.CreateChallengeAsync(Request());
        var response = await ResponseAsync(challenge);
        return (response, await Service.SubmitAsync(response));
    }
    public HeartbeatAuditAgent Agent(IHeartbeatAuditTransport? transport = null, IAuditableTelemetryCache? cache = null, HeartbeatAgentOptions? options = null) =>
        new(NodeId, LedgerId, cache ?? Ledger.Cache, () => Metrics, transport ?? Service, Ledger.Local.Node, Ledger.Local.Server,
            options, Clock, RunId);
    public async ValueTask DisposeAsync()
    {
        if (Store is not null) await Store.DisposeAsync();
        if (Ledger is not null) await Ledger.DisposeAsync();
    }
}
internal sealed class AuditTransportDecorator(IHeartbeatAuditTransport inner) : IHeartbeatAuditService
{
    public Func<SignedAuditRequest, CancellationToken, Task<SignedAuditChallenge>>? OnChallenge { get; set; }
    public Func<SignedAuditResponse, CancellationToken, Task<SignedAuditResult>>? OnResponse { get; set; }
    public Func<SignedHealthQuery, CancellationToken, Task<SignedNodeHealth>>? OnHealth { get; set; }
    public Task<SignedAuditChallenge> CreateChallengeAsync(SignedAuditRequest request, CancellationToken cancellationToken = default) =>
        OnChallenge?.Invoke(request, cancellationToken) ?? inner.CreateChallengeAsync(request, cancellationToken);
    public Task<SignedAuditResult> SubmitAsync(SignedAuditResponse response, CancellationToken cancellationToken = default) =>
        OnResponse?.Invoke(response, cancellationToken) ?? inner.SubmitAsync(response, cancellationToken);
    public Task<SignedNodeHealth> GetHealthAsync(SignedHealthQuery query, CancellationToken cancellationToken = default) =>
        OnHealth?.Invoke(query, cancellationToken) ?? inner.GetHealthAsync(query, cancellationToken);
}
