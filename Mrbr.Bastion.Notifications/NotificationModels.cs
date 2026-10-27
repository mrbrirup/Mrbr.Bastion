using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Mrbr.Bastion.Alerting;

namespace Mrbr.Bastion.Notifications;

public enum NotificationState { Pending, InFlight, Delivered, DeadLetter }
public enum NotificationDisposition { Accepted, Retry, PermanentFailure }
public enum NotificationAttemptOutcome { Started, Accepted, Retry, PermanentFailure, LeaseExpired }
public sealed record NotificationRoute(string Id, string Fingerprint, bool ReplayExistingEvents = false,
    AlertSeverity MinimumSeverity = AlertSeverity.Warning, bool IncludeAcknowledgements = false)
{
    public void Validate()
    {
        if (string.IsNullOrEmpty(Id) || Id.Length > 64 || Id.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-'))
            || Fingerprint.Length != 64 || Fingerprint.Any(c => !char.IsAsciiHexDigitUpper(c)) || !Enum.IsDefined(MinimumSeverity)) throw new ArgumentException("Invalid notification route.");
    }
    public bool Matches(AlertTransition change) => change.Alert.Severity >= MinimumSeverity
        && (change.Event.Kind != AlertEventKind.Acknowledged || IncludeAcknowledgements);
    public static string HashDestination(params string[] identity) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity)));
}
public sealed record AlertNotification(int Version, Guid DeliveryId, Guid AlertFeedId, string RouteId, AlertTransition Transition);
public static class NotificationJson
{
    public const int MaximumBytes = 32768;
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    { PropertyNameCaseInsensitive = false, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 20, Converters = { new JsonStringEnumConverter(allowIntegerValues: false) } };
    public static byte[] Encode(AlertNotification message)
    { Validate(message); var bytes = JsonSerializer.SerializeToUtf8Bytes(message, Options); if (bytes.Length > MaximumBytes) throw new InvalidDataException("Notification too large."); return bytes; }
    public static AlertNotification Decode(ReadOnlySpan<byte> body)
    {
        if (body.Length is < 1 or > MaximumBytes) throw new InvalidDataException("Invalid notification size.");
        try { var value = JsonSerializer.Deserialize<AlertNotification>(body, Options); Validate(value); return value!; }
        catch (JsonException error) { throw new InvalidDataException("Invalid notification document.", error); }
    }
    private static void Validate(AlertNotification? message)
    {
        if (message is null || message.Version != 1 || message.DeliveryId == Guid.Empty || message.AlertFeedId == Guid.Empty
            || string.IsNullOrWhiteSpace(message.RouteId) || message.RouteId.Length > 64) throw new InvalidDataException("Invalid notification identity.");
        AlertTransitionJson.Validate(message.Transition);
    }
}
public sealed record NotificationResult(NotificationDisposition Disposition, string Code, int? RemoteStatus = null, TimeSpan? RetryAfter = null)
{
    public static NotificationResult Accepted() => new(NotificationDisposition.Accepted, "ProviderAccepted");
    public static NotificationResult Retry(string code, int? status = null, TimeSpan? retryAfter = null) => new(NotificationDisposition.Retry, code, status, retryAfter);
    public static NotificationResult Permanent(string code, int? status = null) => new(NotificationDisposition.PermanentFailure, code, status);
}
public interface INotificationTransport : IDisposable
{
    NotificationRoute Route { get; }
    Task<NotificationResult> SendAsync(AlertNotification notification, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default);
}
public sealed record NotificationSubscription(NotificationRoute Route, Guid FeedId, long Cursor);
public sealed record NotificationDelivery(long Sequence, Guid Id, string RouteId, Guid FeedId, long EventId, long AlertId,
    string NodeId, Guid LedgerId, AlertEventKind EventKind, NotificationState State, int Attempts, int CycleAttempts,
    int MaximumAttempts, int Redrives, int MaximumRedrives, DateTimeOffset CreatedUtc, DateTimeOffset NextAttemptUtc,
    DateTimeOffset? DeliveredUtc, string? LastCode, DateTimeOffset? LeaseExpiresUtc = null);
public sealed record NotificationLease(NotificationDelivery Delivery, Guid Token, DateTimeOffset ExpiresUtc, byte[] Body);
public sealed record NotificationAttempt(long Id, Guid DeliveryId, int Number, DateTimeOffset StartedUtc,
    DateTimeOffset? CompletedUtc, NotificationAttemptOutcome Outcome, string? Code, int? RemoteStatus);
public sealed record NotificationRedrive(long Id, Guid DeliveryId, DateTimeOffset RequestedUtc, string Actor);
public sealed record NotificationDetail(NotificationDelivery Delivery, NotificationAttempt[] Attempts, NotificationRedrive[] Redrives);
public sealed record NotificationQuery(NotificationState? State = null, string? RouteId = null, long? BeforeSequence = null,
    int Limit = 25, long? AlertId = null);
public sealed record NotificationPage(NotificationDelivery[] Deliveries, long? NextBeforeSequence);
public sealed record NotificationCounts(long Pending, long InFlight, long Delivered, long DeadLetter);
public interface INotificationReader
{
    Task<NotificationPage> ReadAsync(NotificationQuery query, CancellationToken cancellationToken = default);
    Task<NotificationDetail?> ReadDetailAsync(Guid id, CancellationToken cancellationToken = default);
    Task<NotificationCounts> CountAsync(CancellationToken cancellationToken = default);
}
public interface INotificationQueue : INotificationReader, IAsyncDisposable
{
    Task RegisterAsync(NotificationRoute route, AlertFeedPosition position, CancellationToken cancellationToken = default);
    Task<NotificationSubscription> ReadSubscriptionAsync(string routeId, CancellationToken cancellationToken = default);
    Task AppendAsync(NotificationRoute route, long expectedCursor, AlertFeedPage page, DateTimeOffset now,
        int maximumAttempts, CancellationToken cancellationToken = default);
    Task<NotificationLease?> LeaseAsync(IReadOnlyCollection<string> activeRouteIds, DateTimeOffset now, TimeSpan duration, CancellationToken cancellationToken = default);
    Task CompleteAsync(NotificationLease lease, NotificationResult result, DateTimeOffset now, DateTimeOffset nextAttemptUtc, CancellationToken cancellationToken = default);
    Task<NotificationDelivery?> RedriveAsync(Guid id, string actor, DateTimeOffset now, CancellationToken cancellationToken = default);
}
public sealed record NotificationWorkerStatus(bool Enabled, DateTimeOffset? LastStartedUtc, DateTimeOffset? LastCompletedUtc,
    string? RoutingError, string? DeliveryError, string[] ActiveRoutes);
public interface INotificationMonitor { NotificationWorkerStatus Status { get; } }
public sealed class DisabledNotificationMonitor : INotificationMonitor
{ public NotificationWorkerStatus Status => new(false, null, null, null, null, []); }
public sealed class NotificationConflictException(string code) : Exception(code)
{ public string Code { get; } = code; }
