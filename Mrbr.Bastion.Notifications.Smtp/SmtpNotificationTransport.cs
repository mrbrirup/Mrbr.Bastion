using System.Net;
using System.Net.Sockets;
using System.Text;
using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mrbr.Bastion.Alerting;

namespace Mrbr.Bastion.Notifications.Smtp;

public enum SmtpSecurity { StartTls, SslOnConnect, InsecureLoopback }
public sealed record SmtpNotificationOptions
{
    public required string RouteId { get; init; }
    public required string Host { get; init; }
    public int Port { get; init; } = 587;
    public SmtpSecurity Security { get; init; } = SmtpSecurity.StartTls;
    public required string From { get; init; }
    public required string To { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
    public bool AllowInsecureLoopback { get; init; }
    public bool ReplayExistingEvents { get; init; }
    public AlertSeverity MinimumSeverity { get; init; } = AlertSeverity.Warning;
    public bool IncludeAcknowledgements { get; init; }
}

/// <summary>One recipient per route isolates partial recipient rejection and keeps retry ownership unambiguous.</summary>
public sealed class SmtpNotificationTransport : INotificationTransport
{
    private readonly SmtpNotificationOptions _options;
    private readonly MailboxAddress _from, _to;
    public NotificationRoute Route { get; }
    public SmtpNotificationTransport(SmtpNotificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.Host) || options.Host.Length > 253 || options.Host.Any(char.IsWhiteSpace)
            || options.Host.Any(c => c is '\r' or '\n' or '\0') || options.Port is < 1 or > 65535 || !Enum.IsDefined(options.Security)
            || !ValidMailbox(options.From) || !ValidMailbox(options.To) || options.Username?.Length > 1024 || options.Password?.Length > 4096
            || string.IsNullOrEmpty(options.Username) != string.IsNullOrEmpty(options.Password)
            || (options.Security == SmtpSecurity.InsecureLoopback && (!options.AllowInsecureLoopback
                || !IPAddress.TryParse(options.Host, out var ip) || !IPAddress.IsLoopback(ip)))) throw new ArgumentException("Invalid SMTP destination configuration.", nameof(options));
        _options = options; _from = MailboxAddress.Parse(options.From); _to = MailboxAddress.Parse(options.To);
        Route = new(options.RouteId, NotificationRoute.HashDestination("smtp", options.Host.ToLowerInvariant(), options.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            options.Security.ToString(), _from.Address, _to.Address), options.ReplayExistingEvents, options.MinimumSeverity, options.IncludeAcknowledgements); Route.Validate();
    }
    private static bool ValidMailbox(string? value) => value is { Length: > 0 and <= 320 } && !value.Any(c => c is '\r' or '\n' or '\0') && MailboxAddress.TryParse(value, out _);
    public async Task<NotificationResult> SendAsync(AlertNotification notification, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default)
    {
        if (notification.RouteId != Route.Id || body.Length > NotificationJson.MaximumBytes) return NotificationResult.Permanent("InvalidNotificationBinding");
        using var message = new MimeMessage(); var a = notification.Transition.Alert; var e = notification.Transition.Event;
        message.From.Add(_from); message.To.Add(_to); message.Date = e.OccurredUtc;
        message.MessageId = "bastion-" + notification.DeliveryId.ToString("N") + "@bastion.invalid";
        message.Subject = $"[Mrbr.Bastion] {e.Kind} {a.Severity}: {a.Code}"+(a.Subject.Length>0?" · "+a.Subject:"");
        message.Headers.Add("X-Bastion-Delivery-Id", notification.DeliveryId.ToString("D"));
        message.Body = new TextPart("plain") { Text = $"Mrbr.Bastion alert {e.Kind}\n\nServer: {a.NodeId}\nLedger: {a.LedgerId:D}\nCategory: {a.Category}\nCondition: {a.Code}\nSubject: {a.Subject}\nSeverity: {a.Severity}\nEvent time (UTC): {e.OccurredUtc:O}\nDelivery ID: {notification.DeliveryId:D}\n\n" + Encoding.UTF8.GetString(body.Span) };
        using var client = new SmtpClient { Timeout = 30000 };
        try
        {
            var mode = _options.Security switch { SmtpSecurity.StartTls => SecureSocketOptions.StartTls,
                SmtpSecurity.SslOnConnect => SecureSocketOptions.SslOnConnect, _ => SecureSocketOptions.None };
            await client.ConnectAsync(_options.Host, _options.Port, mode, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(_options.Username)) await client.AuthenticateAsync(_options.Username, _options.Password!, cancellationToken).ConfigureAwait(false);
            await client.SendAsync(message, cancellationToken).ConfigureAwait(false);
            // DATA was accepted. QUIT failure must not turn that acknowledgement into another delivery attempt.
            try { await client.DisconnectAsync(true, cancellationToken).ConfigureAwait(false); }
            catch (Exception) { }
            return NotificationResult.Accepted();
        }
        catch (OperationCanceledException) { throw; }
        catch (SmtpCommandException error)
        {
            int status = (int)error.StatusCode;
            return status is >= 400 and <= 499 ? NotificationResult.Retry("SmtpTransientFailure", status)
                : NotificationResult.Permanent("SmtpPermanentFailure", status is >= 100 and <= 599 ? status : null);
        }
        catch (MailKit.Security.AuthenticationException) { return NotificationResult.Permanent("SmtpAuthenticationFailed"); }
        catch (SslHandshakeException) { return NotificationResult.Permanent("SmtpTlsNegotiationFailed"); }
        catch (NotSupportedException) { return NotificationResult.Permanent("SmtpRequiredTlsUnavailable"); }
        catch (SmtpProtocolException) { return NotificationResult.Retry("SmtpProtocolFailure"); }
        catch (IOException) { return NotificationResult.Retry("SmtpConnectionFailure"); }
        catch (SocketException) { return NotificationResult.Retry("SmtpConnectionFailure"); }
    }
    public void Dispose() { }
}
