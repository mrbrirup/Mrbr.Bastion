using Mrbr.Bastion.Auditing.Contracts;

namespace Mrbr.Bastion.Health;

public sealed record HealthScoringOptions
{
    public TimeSpan StaleAfter { get; init; } = TimeSpan.FromSeconds(90);
    public TimeSpan OfflineAfter { get; init; } = TimeSpan.FromMinutes(5);
}
public interface IServerHealthScorer
{
    HealthAssessment Evaluate(AuditResultContent? latest, DateTimeOffset now);
}
/// <summary>Monitoring-health policy. Scores are diagnostic priorities and do not assert a host is uncompromised.</summary>
public sealed class ServerHealthScorer : IServerHealthScorer
{
    public const string PolicyVersion = "mrbr.bastion.monitoring-health.v1";
    private readonly HealthScoringOptions _options;
    public ServerHealthScorer(HealthScoringOptions? options = null)
    {
        _options = options ?? new();
        if (_options.StaleAfter <= TimeSpan.Zero || _options.OfflineAfter <= _options.StaleAfter) throw new ArgumentOutOfRangeException(nameof(options));
    }
    public HealthAssessment Evaluate(AuditResultContent? latest, DateTimeOffset now)
    {
        if (latest is null) return Assessment(ServerHealthState.Unknown, null, [AuditFinding.NoHeartbeat]);
        if (now < latest.AcceptedUtc) return Assessment(ServerHealthState.Unknown, null,
            AuditProtocol.Normalize(latest.Findings.Append(AuditFinding.ServerClockInconsistent)));
        var findings = latest.Findings.AsEnumerable();
        var age = now - latest.AcceptedUtc;
        if (age >= _options.OfflineAfter) return Assessment(ServerHealthState.Offline, 0,
            AuditProtocol.Normalize(findings.Append(AuditFinding.Offline)));
        if (age >= _options.StaleAfter) findings = findings.Append(AuditFinding.StaleHeartbeat);
        var normalized = AuditProtocol.Normalize(findings);
        int score = Math.Clamp(100 - normalized.Sum(Penalty), 0, 100);
        var state = normalized.Any(IsCritical) || score < 50 ? ServerHealthState.Critical
            : normalized.Any(f => Penalty(f) > 0) ? ServerHealthState.Degraded : ServerHealthState.Healthy;
        return Assessment(state, score, normalized);
    }
    private HealthAssessment Assessment(ServerHealthState state, int? score, AuditFinding[] findings) =>
        new(PolicyVersion, state, score, findings, (long)_options.StaleAfter.TotalMilliseconds, (long)_options.OfflineAfter.TotalMilliseconds);
    public static int Penalty(AuditFinding finding) => finding switch
    {
        AuditFinding.LocalLedgerRollback or AuditFinding.CheckpointHashMismatch => 80,
        AuditFinding.LocalCacheIntegrityFailure => 70,
        AuditFinding.CollectorFaulted => 50,
        AuditFinding.CollectorStopped or AuditFinding.CollectorNotStarted or AuditFinding.StaleHeartbeat => 40,
        AuditFinding.CounterRollback => 30,
        AuditFinding.EventsLost or AuditFinding.CacheAuditUnavailable => 25,
        AuditFinding.ClockSkewOrDelay or AuditFinding.LargeBacklog => 15,
        AuditFinding.Offline => 100,
        _ => 0
    };
    public static bool IsCritical(AuditFinding finding) => finding is AuditFinding.LocalLedgerRollback
        or AuditFinding.CheckpointHashMismatch or AuditFinding.LocalCacheIntegrityFailure or AuditFinding.CollectorFaulted;
}
