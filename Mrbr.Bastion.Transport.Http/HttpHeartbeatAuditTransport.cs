using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing.Contracts;

namespace Mrbr.Bastion.Transport.Http;

public sealed class HttpHeartbeatAuditTransport : IHeartbeatAuditTransport, IDisposable
{
    private readonly HttpClient _client;
    private readonly Uri _baseAddress;
    private readonly TelemetryTransportOptions _options;
    private readonly ISignatureVerifier _verifier;
    public HttpHeartbeatAuditTransport(Uri serviceAddress, ISignatureVerifier serverVerifier,
        TelemetryTransportOptions? options = null, HttpMessageHandler? handler = null)
    {
        _verifier = serverVerifier ?? throw new ArgumentNullException(nameof(serverVerifier));
        _options = options ?? new(); _options.ValidateAddress(serviceAddress);
        handler ??= new SocketsHttpHandler { AllowAutoRedirect = false };
        if (handler is SocketsHttpHandler sockets) sockets.AllowAutoRedirect = false;
        if (handler is HttpClientHandler standard) standard.AllowAutoRedirect = false;
        _client = new(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        _baseAddress = new Uri(serviceAddress.AbsoluteUri.TrimEnd('/') + "/");
    }
    public async Task<SignedAuditChallenge> CreateChallengeAsync(SignedAuditRequest request, CancellationToken cancellationToken = default)
    {
        var result = await Send<SignedAuditRequest, SignedAuditChallenge>("challenges", request, cancellationToken).ConfigureAwait(false);
        if (!AuditProtocol.Verify(result, _verifier)) throw Invalid();
        try { AuditProtocol.Bind(result, request); } catch (InvalidDataException error) { throw Invalid(error); }
        return result;
    }
    public async Task<SignedAuditResult> SubmitAsync(SignedAuditResponse response, CancellationToken cancellationToken = default)
    {
        var result = await Send<SignedAuditResponse, SignedAuditResult>("responses", response, cancellationToken).ConfigureAwait(false);
        if (!AuditProtocol.Verify(result, _verifier)) throw Invalid();
        try { AuditProtocol.Bind(result, response); } catch (InvalidDataException error) { throw Invalid(error); }
        return result;
    }
    public async Task<SignedNodeHealth> GetHealthAsync(SignedHealthQuery query, CancellationToken cancellationToken = default)
    {
        var result = await Send<SignedHealthQuery, SignedNodeHealth>("health", query, cancellationToken).ConfigureAwait(false);
        if (!AuditProtocol.Verify(result, _verifier)) throw Invalid();
        try { AuditProtocol.Bind(result, query); } catch (InvalidDataException error) { throw Invalid(error); }
        return result;
    }
    private async Task<TOut> Send<TIn, TOut>(string route, TIn value, CancellationToken cancellationToken)
    {
        byte[] body = TelemetryJson.Encode(value);
        if (body.Length > AuditProtocol.MaximumEnvelopeBytes) throw new TelemetryTransportException("The audit request exceeds its wire limit.", false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(_options.RequestTimeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_baseAddress, "api/v1/audits/" + route)) { Content = new ByteArrayContent(body) };
            request.Content.Headers.ContentType = new("application/json");
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                AuditError? rejection = null;
                if (response.Content.Headers.ContentType?.MediaType == "application/json" && response.Content.Headers.ContentLength is not > 16384)
                {
                    try
                    {
                        await using var errorStream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
                        rejection = await TelemetryJson.ReadAsync<AuditError>(errorStream, 16384, timeout.Token).ConfigureAwait(false);
                    }
                    catch (Exception error) when (error is InvalidDataException or TelemetryMessageTooLargeException) { }
                }
                if (rejection is not null && Enum.IsDefined(rejection.Failure))
                    throw new AuditRejectedException(rejection.Failure, "The receiver rejected the audit: " + rejection.Failure);
                int status = (int)response.StatusCode;
                throw new TelemetryTransportException($"Heartbeat audit returned HTTP {status}.", status is >= 500 or 408 or 429);
            }
            if (response.Content.Headers.ContentLength > AuditProtocol.MaximumEnvelopeBytes
                || !string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)) throw Invalid();
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            return await TelemetryJson.ReadAsync<TOut>(stream, AuditProtocol.MaximumEnvelopeBytes, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new TelemetryTransportException("HTTP audit request timed out.", true); }
        catch (HttpRequestException error) { throw new TelemetryTransportException("HTTP audit delivery failed.", true, error); }
        catch (InvalidDataException error) { throw Invalid(error); }
        catch (TelemetryMessageTooLargeException error) { throw Invalid(error); }
        catch (IOException error) { throw new TelemetryTransportException("The HTTP audit response was interrupted.", true, error); }
    }
    private static TelemetryTransportException Invalid(Exception? error = null) => new("The receiver returned an invalid, mismatched, or oversized signed audit document.", false, error);
    public void Dispose() => _client.Dispose();
}
