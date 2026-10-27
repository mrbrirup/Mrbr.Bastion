using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Alerting.Sqlite;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Operations;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class OperationsTests
{
    [Fact]
    public async Task HistoryUsesStableDescendingCursorsAndReturnsOriginalSignedEvidence()
    {
        await using var f = await AuditFixture.CreateAsync();
        for (int i = 0; i < 5; i++) { await f.AuditAsync(); f.Clock.Advance(TimeSpan.FromSeconds(1)); }
        var first = await f.Store.ReadHistoryAsync(f.NodeId, f.LedgerId, limit: 2);
        Assert.Equal([5L, 4L], first.Records.Select(x => x.Result.Content.AuditSequenceNumber)); Assert.Equal(4, first.NextBeforeSequence);
        await f.AuditAsync();
        var second = await f.Store.ReadHistoryAsync(f.NodeId, f.LedgerId, first.NextBeforeSequence, 2);
        Assert.Equal([3L, 2L], second.Records.Select(x => x.Result.Content.AuditSequenceNumber));
        var last = await f.Store.ReadHistoryAsync(f.NodeId, f.LedgerId, second.NextBeforeSequence, 2);
        Assert.Single(last.Records); Assert.Null(last.NextBeforeSequence);
        Assert.True(AuditProtocol.Verify(last.Records[0].Result, f.Ledger.Local.Server));
        Assert.Empty((await f.Store.ReadHistoryAsync(f.NodeId, f.LedgerId, 1)).Records);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => f.Store.ReadHistoryAsync(f.NodeId, f.LedgerId, limit: 101));
    }
    [Fact]
    public async Task HistoryDoesNotListOutstandingChallengesAndRejectsMissingHistoricalEvidence()
    {
        await using var f = await AuditFixture.CreateAsync();
        await f.AuditAsync(); await f.AuditAsync(); await f.AuditAsync(); await f.Service.CreateChallengeAsync(f.Request());
        Assert.Equal(3, (await f.Store.ReadHistoryAsync(f.NodeId, f.LedgerId)).Records.Length);
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.Options.DatabasePath, Pooling = false }.ToString()); db.Open();
        using var edit = db.CreateCommand(); edit.CommandText = "DELETE FROM audit_entries WHERE accepted_sequence=2"; edit.ExecuteNonQuery();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Store.ReadHistoryAsync(f.NodeId, f.LedgerId));
    }
    [Fact]
    public async Task HistoryVerifiesHistoricalDocumentsOnEveryRead()
    {
        await using var f = await AuditFixture.CreateAsync(); await f.AuditAsync(); await f.AuditAsync();
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.Options.DatabasePath, Pooling = false }.ToString()); db.Open();
        using var edit = db.CreateCommand(); edit.CommandText = "UPDATE audit_entries SET result_json=zeroblob(length(result_json)) WHERE accepted_sequence=1"; edit.ExecuteNonQuery();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Store.ReadHistoryAsync(f.NodeId, f.LedgerId));
    }
    [Fact]
    public async Task FleetQueriesShowUnknownAndFailedVerificationSeparatelyWithoutRefreshingLiveness()
    {
        await using var f = await OperationsFixture.CreateAsync();
        var initial = await f.Service.ReadFleetAsync(); Assert.Equal(1, initial.Summary.Unknown); Assert.Null(initial.Servers[0].Health!.LastAcceptedAuditUtc);
        await f.Audits.AuditAsync();
        var healthy = await f.Service.ReadFleetAsync(state: ServerHealthState.Healthy); Assert.Equal(1, healthy.TotalMatches);
        var accepted = healthy.Servers[0].Health!.LastAcceptedAuditUtc;
        f.Audits.Clock.Advance(TimeSpan.FromSeconds(91));
        Assert.Equal(1, (await f.Service.ReadFleetAsync()).Summary.Degraded);
        Assert.Equal(accepted, (await f.Service.ReadServerAsync(f.NodeId, f.LedgerId)).Health!.LastAcceptedAuditUtc);
        f.Reader.Fail = true;
        var unavailable = await f.Service.ReadFleetAsync(); Assert.Equal(1, unavailable.Summary.VerificationUnavailable); Assert.Equal(0, unavailable.Summary.Healthy);
        Assert.Null(unavailable.Servers[0].Health); Assert.Equal(HealthAlertPolicy.VerificationUnavailable, unavailable.Servers[0].Error);
    }
    [Fact]
    public async Task InventoryAndQueriesAreBoundedAndRequireEnrollment()
    {
        await using var f = await OperationsFixture.CreateAsync();
        Assert.Single((await f.Service.ReadFleetAsync(search: "TEST" )).Servers);
        Assert.Empty((await f.Service.ReadFleetAsync(search: "missing")).Servers);
        await Assert.ThrowsAsync<ArgumentException>(() => f.Service.ReadFleetAsync(pageSize: 101));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => f.Service.ReadServerAsync("unknown", f.LedgerId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => f.Service.ReadHistoryAsync(f.NodeId, Guid.NewGuid()));
        Assert.Throws<ArgumentException>(() => new ServerInventory([new(f.NodeId, f.LedgerId, "one"), new(f.NodeId, f.LedgerId, "two")]));
    }
    [Fact]
    public async Task EvaluatorCreatesConditionsWithoutBrowserReadsAndPreservesThemOnVerificationFailure()
    {
        await using var f = await OperationsFixture.CreateAsync();
        f.Audits.Metrics = f.Audits.Metrics with { State = MonitorState.Stopped }; await f.Audits.AuditAsync(); await f.Evaluator.EvaluateAsync();
        var initial = Assert.Single((await f.Alerts.ReadAsync(new())).Alerts); Assert.Equal("CollectorStopped", initial.Code);
        f.Reader.Fail = true; f.Audits.Clock.Advance(TimeSpan.FromSeconds(1)); await f.Evaluator.EvaluateAsync();
        var failed = (await f.Alerts.ReadAsync(new(ActiveOnly: true))).Alerts;
        Assert.Equal(2, failed.Length); Assert.Contains(failed, a => a.Id == initial.Id); Assert.Contains(failed, a => a.Code == HealthAlertPolicy.VerificationUnavailable);
        Assert.Equal(1, f.Evaluator.Status.FailedServers); Assert.NotNull(f.Evaluator.Status.Error);
        f.Reader.Fail = false; f.Audits.Metrics = f.Audits.Metrics with { State = MonitorState.Running }; await f.Audits.AuditAsync(); await f.Evaluator.EvaluateAsync();
        Assert.Empty((await f.Alerts.ReadAsync(new(ActiveOnly: true))).Alerts); Assert.Equal(2, (await f.Alerts.CountAsync()).Resolved); Assert.Null(f.Evaluator.Status.Error);
    }
    [Fact]
    public async Task EvaluatorCancellationDoesNotCreateVerificationFailureAlerts()
    {
        await using var f = await OperationsFixture.CreateAsync(); using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Evaluator.EvaluateAsync(canceled.Token));
        Assert.Empty((await f.Alerts.ReadAsync(new())).Alerts);
    }
    [Fact]
    public async Task AlertPersistenceFailureIsVisibleAndDoesNotErasePreviouslyActiveAlerts()
    {
        await using var f = await OperationsFixture.CreateAsync(); await f.Alerts.DisposeAsync();
        await using var full = await SqliteAlertStore.OpenAsync(new() { DatabasePath = f.DatabasePath, MaximumStoredAlerts = 1 });
        var evaluator = new AlertEvaluator(f.Inventory, f.Reader, full, f.Audits.Clock);
        await evaluator.EvaluateAsync(); f.Reader.Fail = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => evaluator.EvaluateAsync());
        Assert.NotNull(evaluator.Status.Error);
        Assert.Equal("NoHeartbeat", Assert.Single((await full.ReadAsync(new(ActiveOnly: true))).Alerts).Code);
    }
    [Fact]
    public void InformationalChangesDoNotProduceAlertsButOfflineAndIntegrityFailuresAreCritical()
    {
        var health = new HealthAssessment("policy", ServerHealthState.Critical, 0,
            [AuditFinding.CollectorRestarted, AuditFinding.LocalTailAwaitingIngestion, AuditFinding.Offline, AuditFinding.LocalCacheIntegrityFailure], 90000, 300000);
        Assert.All(HealthAlertPolicy.FromHealth(health), a => Assert.Equal(AlertSeverity.Critical, a.Severity));
        Assert.Equal(2, HealthAlertPolicy.FromHealth(health).Length);
    }
}

internal sealed class FailableHealthReader(INodeHealthReader inner) : INodeHealthReader
{
    public bool Fail { get; set; }
    public Task<NodeHealthSnapshot> ReadNodeHealthAsync(string nodeId, Guid ledgerId, CancellationToken cancellationToken = default) =>
        Fail ? throw new InvalidDataException("Test verification failure") : inner.ReadNodeHealthAsync(nodeId, ledgerId, cancellationToken);
}
internal sealed class OperationsFixture : IAsyncDisposable
{
    public AuditFixture Audits { get; private set; } = null!;
    public SqliteAlertStore Alerts { get; private set; } = null!;
    public ServerInventory Inventory { get; private set; } = null!;
    public FailableHealthReader Reader { get; private set; } = null!;
    public OperationsService Service { get; private set; } = null!;
    public AlertEvaluator Evaluator { get; private set; } = null!;
    public string NodeId => Audits.NodeId; public Guid LedgerId => Audits.LedgerId;
    public string DatabasePath => Path.Combine(Audits.Ledger.Local.DirectoryPath, "alerts.db");
    public static async Task<OperationsFixture> CreateAsync()
    {
        var f = new OperationsFixture();
        try
        {
            f.Audits = await AuditFixture.CreateAsync(); f.Alerts = await SqliteAlertStore.OpenAsync(new() { DatabasePath = f.DatabasePath });
            f.Inventory = new([new(f.NodeId, f.LedgerId, "Test server")]); f.Reader = new(f.Audits.Service);
            f.Service = new(f.Inventory, f.Reader, f.Audits.Store, f.Alerts, f.Audits.Clock);
            f.Evaluator = new(f.Inventory, f.Reader, f.Alerts, f.Audits.Clock); return f;
        }
        catch { await f.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync()
    { if (Alerts is not null) await Alerts.DisposeAsync(); if (Audits is not null) await Audits.DisposeAsync(); }
}
