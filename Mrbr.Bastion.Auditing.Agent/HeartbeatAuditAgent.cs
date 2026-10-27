using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing.Contracts;

namespace Mrbr.Bastion.Auditing.Agent;

public sealed record HeartbeatAgentOptions
{
    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan InitialRetryDelay { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan MaximumRetryDelay { get; init; } = TimeSpan.FromSeconds(30);
}
public sealed record HeartbeatAgentHealth(long CompletedAudits, long TransientFailures, DateTimeOffset? LastAcceptedUtc,
    HealthAssessment? LastHealth, string? LastError);

/// <summary>One identity per collector lifetime. Retries retain the exact request/response until consumed or expired.</summary>
public sealed class HeartbeatAuditAgent
{
    private readonly string _nodeId;
    private readonly Guid _ledgerId;
    private readonly Guid _runId;
    private readonly IAuditableTelemetryCache _cache;
    private readonly Func<MonitorHealth> _health;
    private readonly IHeartbeatAuditTransport _transport;
    private readonly ISignatureSigner _signer;
    private readonly ISignatureVerifier _serverVerifier;
    private readonly HeartbeatAgentOptions _options;
    private readonly TimeProvider _time;
    private readonly long _started;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SignedAuditRequest? _request;
    private SignedAuditResponse? _response;
    private SignedAuditResult? _lastResult;
    private SignedNodeHealth? _lastHealth;
    private long _completed, _failures;
    private string? _lastError;
    private int _running;
    public HeartbeatAuditAgent(string nodeId, Guid ledgerId, IAuditableTelemetryCache cache, Func<MonitorHealth> collectorHealth,
        IHeartbeatAuditTransport transport, ISignatureSigner nodeSigner, ISignatureVerifier serverVerifier,
        HeartbeatAgentOptions? options = null, TimeProvider? timeProvider = null, Guid? collectorRunId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        if (nodeId.Length > 256 || ledgerId == Guid.Empty || collectorRunId == Guid.Empty) throw new ArgumentException("Invalid audit agent identity.");
        _nodeId = nodeId; _ledgerId = ledgerId; _runId = collectorRunId ?? Guid.NewGuid();
        _cache = cache ?? throw new ArgumentNullException(nameof(cache)); _health = collectorHealth ?? throw new ArgumentNullException(nameof(collectorHealth));
        _transport = transport ?? throw new ArgumentNullException(nameof(transport)); _signer = nodeSigner ?? throw new ArgumentNullException(nameof(nodeSigner));
        _serverVerifier = serverVerifier ?? throw new ArgumentNullException(nameof(serverVerifier));
        _options = options ?? new();
        if (_options.Interval <= TimeSpan.Zero || _options.Interval > TimeSpan.FromHours(1) || _options.InitialRetryDelay <= TimeSpan.Zero
            || _options.MaximumRetryDelay < _options.InitialRetryDelay || _options.MaximumRetryDelay > TimeSpan.FromMinutes(5)) throw new ArgumentOutOfRangeException(nameof(options));
        _time = timeProvider ?? TimeProvider.System; _started = _time.GetTimestamp();
    }
    public HeartbeatAgentHealth GetHealth()
    {
        var assessment = Volatile.Read(ref _lastHealth)?.Content.Assessment;
        return new(Interlocked.Read(ref _completed), Interlocked.Read(ref _failures), Volatile.Read(ref _lastResult)?.Content.AcceptedUtc,
            assessment is null ? null : assessment with { Findings = assessment.Findings.ToArray() }, Volatile.Read(ref _lastError));
    }
    public async Task<SignedAuditResult> AuditOnceAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_request is null)
            {
                var c = new AuditRequestContent(1, _nodeId, _ledgerId, Guid.NewGuid(), _runId, _time.GetUtcNow(), _signer.Algorithm, _signer.KeyId);
                _request = new(c, _signer.Sign(AuditProtocol.Encode(c)));
            }
            if (_response is null)
            {
                var challenge = await _transport.CreateChallengeAsync(_request, cancellationToken).ConfigureAwait(false);
                if (!AuditProtocol.Verify(challenge, _serverVerifier)) throw Invalid("The audit challenge signature is not trusted.");
                try { AuditProtocol.Bind(challenge, _request); }
                catch (InvalidDataException error) { throw Invalid("The receiver returned a challenge for a different request.", error); }
                CacheAuditObservation observation;
                try
                {
                    var snapshot = await _cache.CaptureAuditSnapshotAsync(challenge.Content.Anchor, cancellationToken).ConfigureAwait(false);
                    observation = new(CacheAuditOutcome.Verified, _time.GetUtcNow(), snapshot);
                }
                catch (InvalidDataException) { observation = new(CacheAuditOutcome.IntegrityFailed, _time.GetUtcNow(), null); }
                catch (Exception error) when (error is not OperationCanceledException and not OutOfMemoryException)
                { observation = new(CacheAuditOutcome.Unavailable, _time.GetUtcNow(), null); }
                var content = new AuditResponseContent(1, _nodeId, _ledgerId, _runId, challenge.Content.ChallengeId,
                    AuditProtocol.Hash(AuditProtocol.Encode(challenge.Content)), challenge.Content.Nonce.ToArray(), _time.GetUtcNow(),
                    checked((long)_time.GetElapsedTime(_started).TotalMilliseconds), CollectorMetrics.FromHealth(_health()), observation, _signer.Algorithm, _signer.KeyId);
                _response = new(content, _signer.Sign(AuditProtocol.Encode(content)));
            }
            var result = await _transport.SubmitAsync(_response, cancellationToken).ConfigureAwait(false);
            if (!AuditProtocol.Verify(result, _serverVerifier)) throw Invalid("The audit assessment signature is not trusted.");
            try { AuditProtocol.Bind(result, _response); }
            catch (InvalidDataException error) { throw Invalid("The audit assessment does not identify this signed response.", error); }
            if (_lastResult is not null && result.Content.AuditSequenceNumber <= _lastResult.Content.AuditSequenceNumber)
                throw Invalid("The receiver's audit sequence did not advance.");
            Volatile.Write(ref _lastResult, result with { Content = result.Content with { Findings = result.Content.Findings.ToArray() }, Signature = result.Signature.ToArray() });
            _request = null; _response = null; Interlocked.Increment(ref _completed); Volatile.Write(ref _lastError, null);
            return result;
        }
        catch (AuditRejectedException error) when (error.Failure == AuditFailure.ChallengeExpired)
        { _request = null; _response = null; Volatile.Write(ref _lastError, error.Message); throw; }
        catch (Exception error) { Volatile.Write(ref _lastError, error.Message); throw; }
        finally { _gate.Release(); }
    }
    public async Task<SignedNodeHealth> RefreshHealthAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var content = new HealthQueryContent(1, _nodeId, _ledgerId, Guid.NewGuid(), _time.GetUtcNow(), _signer.Algorithm, _signer.KeyId);
            var query = new SignedHealthQuery(content, _signer.Sign(AuditProtocol.Encode(content)));
            var health = await _transport.GetHealthAsync(query, cancellationToken).ConfigureAwait(false);
            if (!AuditProtocol.Verify(health, _serverVerifier)) throw Invalid("The health projection signature is not trusted.");
            try { AuditProtocol.Bind(health, query); }
            catch (InvalidDataException error) { throw Invalid("The health projection does not identify this query.", error); }
            if (_lastResult is { } last && (health.Content.LastAuditSequenceNumber is null
                || health.Content.LastAuditSequenceNumber < last.Content.AuditSequenceNumber
                || (health.Content.LastAuditSequenceNumber == last.Content.AuditSequenceNumber
                    && health.Content.LastResultHash != AuditProtocol.Hash(AuditProtocol.Encode(last.Content)))))
                throw Invalid("The receiver's health history regressed or changed.");
            Volatile.Write(ref _lastHealth, health with { Content = health.Content with { Assessment = health.Content.Assessment with { Findings = health.Content.Assessment.Findings.ToArray() } }, Signature = health.Signature.ToArray() });
            Volatile.Write(ref _lastError, null); return health;
        }
        catch (Exception error) { Volatile.Write(ref _lastError, error.Message); throw; }
        finally { _gate.Release(); }
    }
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _running, 1) != 0) throw new InvalidOperationException("An audit agent can only run once.");
        double retry = _options.InitialRetryDelay.TotalMilliseconds;
        bool needsHealthRead = false;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (!needsHealthRead) { await AuditOnceAsync(cancellationToken).ConfigureAwait(false); needsHealthRead = true; }
                    await RefreshHealthAsync(cancellationToken).ConfigureAwait(false); needsHealthRead = false;
                    retry = _options.InitialRetryDelay.TotalMilliseconds;
                    await Task.Delay(_options.Interval, _time, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception error) when (error is TelemetryTransportException { IsTransient: true }
                    || error is AuditRejectedException { IsTransient: true } or AuditRejectedException { Failure: AuditFailure.ChallengeExpired })
                {
                    Volatile.Write(ref _lastError, error.Message); Interlocked.Increment(ref _failures);
                    await Task.Delay(TimeSpan.FromMilliseconds(retry * (0.8 + Random.Shared.NextDouble() * 0.2)), _time, cancellationToken).ConfigureAwait(false);
                    retry = Math.Min(retry * 2, _options.MaximumRetryDelay.TotalMilliseconds);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }
    private static TelemetryTransportException Invalid(string message, Exception? error = null) => new(message, false, error);
}
