using System.Net.Http.Headers;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Transport.Http;

/// <summary>Reusable HTTP/JSON transport. Redirects are disabled; normal TLS validation is preserved.</summary>
public sealed class HttpTelemetryTransport : ITelemetryTransport, IDisposable
{
    private readonly HttpClient _client;
    private readonly Uri _endpoint;
    private readonly ISignatureVerifier _verifier;
    private readonly TelemetryTransportOptions _options;
    public HttpTelemetryTransport(Uri serviceAddress, ISignatureVerifier receiptVerifier, TelemetryTransportOptions? options = null, HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(receiptVerifier);
        _options = options ?? new();
        _options.ValidateAddress(serviceAddress);
        handler ??= new SocketsHttpHandler { AllowAutoRedirect = false };
        if (handler is SocketsHttpHandler sockets) sockets.AllowAutoRedirect = false;
        if (handler is HttpClientHandler standard) standard.AllowAutoRedirect = false;
        _client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        _verifier = receiptVerifier;
        _endpoint = new Uri(new Uri(serviceAddress.AbsoluteUri.TrimEnd('/') + "/"), "api/v1/telemetry/blocks");
    }
    public async Task<SettlementReceipt> SubmitAsync(SignedTelemetryBlock block, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(block);
        byte[] body = TelemetryJson.Encode(block);
        if (body.Length > TelemetryJson.MaximumBlockBytes) throw new TelemetryTransportException("The HTTP block exceeds the wire size limit.", false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.RequestTimeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint) { Content = new ByteArrayContent(body) };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                int status = (int)response.StatusCode;
                throw new TelemetryTransportException($"Telemetry ingestion returned HTTP {status}.", status is >= 500 or 408 or 429);
            }
            if (response.Content.Headers.ContentLength > TelemetryJson.MaximumReceiptBytes)
                throw new TelemetryTransportException("The receiver returned an oversized receipt.", false);
            if (response.Content.Headers.ContentType?.MediaType != "application/json")
                throw new TelemetryTransportException("The receiver did not return a JSON receipt.", false);
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            var receipt = await TelemetryJson.ReadAsync<SettlementReceipt>(stream, TelemetryJson.MaximumReceiptBytes, timeout.Token).ConfigureAwait(false);
            return ReceiptValidation.Verify(receipt, block, _verifier);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new TelemetryTransportException("HTTP telemetry delivery timed out.", true); }
        catch (HttpRequestException error) { throw new TelemetryTransportException("HTTP telemetry delivery failed.", true, error); }
        catch (InvalidDataException error) { throw new TelemetryTransportException("The receiver returned a malformed receipt.", false, error); }
        catch (TelemetryMessageTooLargeException error) { throw new TelemetryTransportException("The receiver returned an oversized receipt.", false, error); }
        catch (IOException error) { throw new TelemetryTransportException("The HTTP response was interrupted.", true, error); }
    }
    public void Dispose() => _client.Dispose();
}
