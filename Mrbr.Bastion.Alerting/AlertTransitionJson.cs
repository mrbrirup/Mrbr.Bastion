using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mrbr.Bastion.Alerting;

public static class AlertTransitionJson
{
    public const int MaximumBytes = 16384;
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 16,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) }
    };
    public static byte[] Encode(AlertTransition transition)
    {
        Validate(transition); var bytes = JsonSerializer.SerializeToUtf8Bytes(transition, Options);
        if (bytes.Length > MaximumBytes) throw new InvalidDataException("The alert transition is too large."); return bytes;
    }
    public static AlertTransition Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 1 or > MaximumBytes) throw new InvalidDataException("Invalid alert transition size.");
        try { var value = JsonSerializer.Deserialize<AlertTransition>(bytes, Options); Validate(value); return value!; }
        catch (JsonException error) { throw new InvalidDataException("Invalid alert transition document.", error); }
    }
    public static void Validate(AlertTransition? transition)
    {
        if (transition?.Event is not { } e || transition.Alert is not { } a || e.Id < 1 || a.Id < 1 || e.AlertId != a.Id
            || !Enum.IsDefined(e.Kind) || !Enum.IsDefined(a.Severity) || string.IsNullOrWhiteSpace(a.NodeId) || a.NodeId.Length > 256
            || a.LedgerId == Guid.Empty || string.IsNullOrWhiteSpace(a.Code) || a.Code.Length > 64
            || a.Code.Any(c => !char.IsAsciiLetterOrDigit(c)) || !Enum.IsDefined(a.Category) || a.Subject is null || a.Subject.Length>160
            || a.Subject.Any(char.IsControl) || e.Actor?.Length > 128 || a.AcknowledgedBy?.Length > 128
            || e.OccurredUtc.Offset != TimeSpan.Zero || a.OpenedUtc.Offset != TimeSpan.Zero || a.LastObservedUtc.Offset != TimeSpan.Zero
            || a.AcknowledgedUtc?.Offset != TimeSpan.Zero && a.AcknowledgedUtc is not null
            || a.ResolvedUtc?.Offset != TimeSpan.Zero && a.ResolvedUtc is not null
            || a.LastObservedUtc < a.OpenedUtc || a.LastObservedUtc > e.OccurredUtc || a.OpenedUtc > e.OccurredUtc
            || (e.Kind == AlertEventKind.Opened && (a.State != AlertState.Open || a.OpenedUtc != e.OccurredUtc))
            || (e.Kind == AlertEventKind.Acknowledged && (a.State != AlertState.Acknowledged || a.AcknowledgedUtc != e.OccurredUtc || a.AcknowledgedBy != e.Actor))
            || (e.Kind == AlertEventKind.Resolved && (a.State != AlertState.Resolved || a.ResolvedUtc != e.OccurredUtc)))
            throw new InvalidDataException("Invalid alert transition metadata.");
    }
}
