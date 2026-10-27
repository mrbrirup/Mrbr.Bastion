using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Mrbr.Bastion.Alerting;

namespace Mrbr.Bastion.Notifications.Webhooks;

public sealed record WebhookNotificationOptions
{
    public required string RouteId { get; init; }
    public required Uri Endpoint { get; init; }
    public string? BearerToken { get; init; }
    public string? SigningKey { get; init; }
    public string SigningKeyId { get; init; } = "default";
    public bool AllowInsecureLoopback { get; init; }
    public bool ReplayExistingEvents { get; init; }
    public AlertSeverity MinimumSeverity { get; init; } = AlertSeverity.Warning;
    public bool IncludeAcknowledgements { get; init; }
}

public static class WebhookSignature
{
    public static string Create(string key, string timestamp, ReadOnlySpan<byte> body)
    {
        byte[] prefix = Encoding.ASCII.GetBytes(timestamp + "."); byte[] signed = new byte[prefix.Length + body.Length];
        prefix.CopyTo(signed, 0); body.CopyTo(signed.AsSpan(prefix.Length));
        return "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), signed));
    }
    public static bool Verify(string key, string timestamp, ReadOnlySpan<byte> body, string signature, DateTimeOffset now, TimeSpan maximumAge)
    {
        if (key.Length < 32 || body.Length > NotificationJson.MaximumBytes || maximumAge <= TimeSpan.Zero || maximumAge > TimeSpan.FromHours(24)
            || !long.TryParse(timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out long seconds) || signature.Length != 71) return false;
        try
        {
            if ((now - DateTimeOffset.FromUnixTimeSeconds(seconds)).Duration() > maximumAge) return false;
            return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Create(key, timestamp, body)), Encoding.ASCII.GetBytes(signature));
        }
        catch (ArgumentOutOfRangeException) { return false; }
    }
}

public sealed class WebhookNotificationTransport : INotificationTransport
{
    private readonly WebhookNotificationOptions _options;
    private readonly HttpClient _client;
    private readonly TimeProvider _time;
    public NotificationRoute Route { get; }
    public WebhookNotificationTransport(WebhookNotificationOptions options, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        bool testHttp = options.AllowInsecureLoopback && options.Endpoint.IsAbsoluteUri && options.Endpoint.Scheme == "http"
            && IPAddress.TryParse(options.Endpoint.Host, out var address) && IPAddress.IsLoopback(address);
        if (!options.Endpoint.IsAbsoluteUri || (options.Endpoint.Scheme != "https" && !testHttp) || options.Endpoint.UserInfo.Length != 0 || options.Endpoint.Fragment.Length != 0
            || options.BearerToken?.Length > 4096 || options.BearerToken?.Any(c => c is '\r' or '\n' or '\0') == true
            || options.SigningKey is { Length: < 32 or > 4096 } || string.IsNullOrEmpty(options.SigningKeyId) || options.SigningKeyId.Length > 64
            || options.SigningKeyId.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_'))) throw new ArgumentException("Invalid webhook destination configuration.", nameof(options));
        _options = options; _time = timeProvider ?? TimeProvider.System;
        Route = new(options.RouteId, NotificationRoute.HashDestination("webhook", options.Endpoint.AbsoluteUri, options.AllowInsecureLoopback.ToString()),
            options.ReplayExistingEvents, options.MinimumSeverity, options.IncludeAcknowledgements); Route.Validate();
        _client = new(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, MaxResponseHeadersLength = 16,
            ConnectTimeout = TimeSpan.FromSeconds(10), PooledConnectionLifetime = TimeSpan.FromMinutes(5) }) { Timeout = Timeout.InfiniteTimeSpan };
    }
    public async Task<NotificationResult> SendAsync(AlertNotification notification, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default)
    {
        if (notification.RouteId != Route.Id || body.Length > NotificationJson.MaximumBytes) return NotificationResult.Permanent("InvalidNotificationBinding");
        using var request = new HttpRequestMessage(HttpMethod.Post, _options.Endpoint);
        request.Content = new ReadOnlyMemoryContent(body); request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation("Idempotency-Key", notification.DeliveryId.ToString("D"));
        request.Headers.TryAddWithoutValidation("X-Bastion-Delivery-Id", notification.DeliveryId.ToString("D"));
        if (!string.IsNullOrEmpty(_options.BearerToken)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.BearerToken);
        if (_options.SigningKey is not null)
        {
            string timestamp = _time.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            request.Headers.TryAddWithoutValidation("X-Bastion-Timestamp", timestamp); request.Headers.TryAddWithoutValidation("X-Bastion-Key-Id", _options.SigningKeyId);
            request.Headers.TryAddWithoutValidation("X-Bastion-Signature", WebhookSignature.Create(_options.SigningKey, timestamp, body.Span));
        }
        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            int status = (int)response.StatusCode;
            if (status is >= 200 and <= 299) return NotificationResult.Accepted();
            if (status is 408 or 425 or 429 || status >= 500)
            {
                var header = response.Headers.RetryAfter;
                var delay = header?.Delta ?? (header?.Date is { } date ? date - _time.GetUtcNow() : (TimeSpan?)null);
                if (delay is { } d) delay = TimeSpan.FromMilliseconds(Math.Clamp(d.TotalMilliseconds, 0, TimeSpan.FromDays(1).TotalMilliseconds));
                return NotificationResult.Retry("HttpTransientFailure", status, delay);
            }
            return NotificationResult.Permanent(status is >= 300 and <= 399 ? "HttpRedirectRejected" : "HttpPermanentFailure", status);
        }
        catch (OperationCanceledException) { throw; }
        catch (HttpRequestException) { return NotificationResult.Retry("HttpConnectionFailure"); }
    }
    public void Dispose() => _client.Dispose();
}
