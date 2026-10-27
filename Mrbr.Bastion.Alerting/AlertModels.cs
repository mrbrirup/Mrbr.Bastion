using Mrbr.Bastion.Auditing.Contracts;

namespace Mrbr.Bastion.Alerting;

public enum AlertSeverity { Warning, Critical }
public enum AlertState { Open, Acknowledged, Resolved }
public enum AlertEventKind { Opened, Acknowledged, Resolved }
public enum AlertCategory { Monitoring, Exposure }
public sealed record AlertCondition(string Code, AlertSeverity Severity,string Subject="",bool PreserveExisting=false);
public sealed record AlertObservation(string NodeId, Guid LedgerId, DateTimeOffset ObservedUtc,
    AlertCondition[] Conditions, bool VerificationSucceeded,AlertCategory Category=AlertCategory.Monitoring,string SubjectPrefix="");
public sealed record ServerAlert(long Id, string NodeId, Guid LedgerId, string Code, AlertSeverity Severity,
    DateTimeOffset OpenedUtc, DateTimeOffset LastObservedUtc, DateTimeOffset? AcknowledgedUtc,
    string? AcknowledgedBy, DateTimeOffset? ResolvedUtc,AlertCategory Category=AlertCategory.Monitoring,string Subject="")
{
    public AlertState State => ResolvedUtc is not null ? AlertState.Resolved : AcknowledgedUtc is not null ? AlertState.Acknowledged : AlertState.Open;
}
public sealed record AlertEvent(long Id, long AlertId, AlertEventKind Kind, DateTimeOffset OccurredUtc, string? Actor);
public sealed record AlertTransition(AlertEvent Event, ServerAlert Alert, bool Reconstructed = false);
public sealed record AlertFeedPosition(Guid FeedId, long LastEventId);
public sealed record AlertFeedPage(AlertFeedPosition Position, AlertTransition[] Changes);
/// <summary>Immutable transition snapshots for durable downstream consumers; reads do not acknowledge or delete events.</summary>
public interface IAlertEventFeed
{
    Task<AlertFeedPosition> ReadPositionAsync(CancellationToken cancellationToken = default);
    Task<AlertFeedPage> ReadChangesAsync(long afterEventId, int limit = 100, CancellationToken cancellationToken = default);
}
public sealed record AlertQuery(string? NodeId = null, Guid? LedgerId = null, AlertState? State = null,
    long? BeforeId = null, int Limit = 25, bool ActiveOnly = false);
public sealed record AlertPage(ServerAlert[] Alerts, long? NextBeforeId);
public sealed record AlertCounts(long Open, long Acknowledged, long Resolved);
public interface IAlertStore : IAsyncDisposable
{
    Task ApplyAsync(AlertObservation observation, CancellationToken cancellationToken = default);
    Task<AlertPage> ReadAsync(AlertQuery query, CancellationToken cancellationToken = default);
    Task<AlertCounts> CountAsync(CancellationToken cancellationToken = default);
    Task<ServerAlert?> AcknowledgeAsync(long id, string actor, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<AlertEvent[]> ReadEventsAsync(long alertId, CancellationToken cancellationToken = default);
}

/// <summary>Maps authenticated monitoring findings to actionable conditions; no notification transport or mitigation.</summary>
public static class HealthAlertPolicy
{
    public const string Version = "mrbr.bastion.health-alerts.v1";
    public const string VerificationUnavailable = "VerificationUnavailable";
    public static AlertCondition[] FromHealth(HealthAssessment health) => health.Findings
        .Where(f => f is not (AuditFinding.CollectorRestarted or AuditFinding.LocalTailAwaitingIngestion))
        .Distinct().Select(f => new AlertCondition(f.ToString(), f is AuditFinding.Offline or AuditFinding.LocalLedgerRollback
            or AuditFinding.CheckpointHashMismatch or AuditFinding.LocalCacheIntegrityFailure or AuditFinding.CollectorFaulted
            ? AlertSeverity.Critical : AlertSeverity.Warning)).OrderBy(c => c.Code, StringComparer.Ordinal).ToArray();
    public static void Validate(AlertObservation value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (string.IsNullOrWhiteSpace(value.NodeId) || value.NodeId.Length > 256 || value.LedgerId == Guid.Empty
            || value.ObservedUtc.Offset != TimeSpan.Zero || !Enum.IsDefined(value.Category) || value.SubjectPrefix is null || value.SubjectPrefix.Length>128
            || value.Category==AlertCategory.Monitoring&&value.SubjectPrefix.Length!=0
            || value.Conditions is null || value.Conditions.Length > (value.Category==AlertCategory.Exposure?20001:32)
            || value.Conditions.Any(c => c is null || !Enum.IsDefined(c.Severity) || c.Subject is null || c.Subject.Length>160
                || !c.Subject.StartsWith(value.SubjectPrefix,StringComparison.Ordinal) || c.Subject.Any(char.IsControl)
                || (value.Category==AlertCategory.Monitoring? !IsKnownCode(c.Code)||c.Subject!=""||c.PreserveExisting : c.Code is not("SoftwareExposure" or "ExposureDataUnavailable")))
            || value.Conditions.Select(c => (c.Code,c.Subject)).Distinct().Count() != value.Conditions.Length
            || (!value.VerificationSucceeded && value.Conditions.Length != 0)) throw new ArgumentException("Invalid alert observation.", nameof(value));
    }
    private static bool IsKnownCode(string code) => Enum.TryParse<AuditFinding>(code, out var finding)
        && Enum.IsDefined(finding) && finding.ToString() == code
        && finding is not (AuditFinding.CollectorRestarted or AuditFinding.LocalTailAwaitingIngestion);
}
