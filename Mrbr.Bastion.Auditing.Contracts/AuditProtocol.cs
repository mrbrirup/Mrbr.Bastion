using System.Security.Cryptography;
using System.Text;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Auditing.Contracts;

/// <summary>Domain-separated canonical v1 encodings. Signatures cover every observation and identity field.</summary>
public static class AuditProtocol
{
    public const int Version = 1;
    public const int MaximumEnvelopeBytes = 128 * 1024;
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);

    public static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    public static byte[] Encode(AuditRequestContent c) => Write("Request", w =>
    {
        Required(c); Identity(w, c.Version, c.NodeId, c.LedgerId, c.Algorithm, c.KeyId);
        Id(w, c.RequestId); Id(w, c.CollectorRunId); Time(w, c.RequestedUtc);
    });
    public static byte[] Encode(AuditChallengeContent c) => Write("Challenge", w =>
    {
        Required(c); Identity(w, c.Version, c.NodeId, c.LedgerId, c.Algorithm, c.KeyId);
        Id(w, c.RequestId); Id(w, c.CollectorRunId); Id(w, c.ChallengeId); HashField(w, c.RequestHash); Nonce(w, c.Nonce);
        Time(w, c.IssuedUtc); Time(w, c.ExpiresUtc);
        if (c.ExpiresUtc <= c.IssuedUtc || c.ExpiresUtc - c.IssuedUtc > TimeSpan.FromMinutes(10)) Invalid("Invalid challenge lifetime.");
        Checkpoint(w, c.Anchor, c.NodeId, c.LedgerId);
    });
    public static byte[] Encode(AuditResponseContent c) => Write("Response", w =>
    {
        Required(c); Identity(w, c.Version, c.NodeId, c.LedgerId, c.Algorithm, c.KeyId);
        Id(w, c.CollectorRunId); Id(w, c.ChallengeId); HashField(w, c.ChallengeHash); Nonce(w, c.Nonce);
        Time(w, c.SampledUtc); Count(w, c.CollectorUptimeMilliseconds);
        Required(c.Collector); EnumField(w, c.Collector.State);
        Count(w, c.Collector.ReceivedEvents); Count(w, c.Collector.FilteredEvents); Count(w, c.Collector.QueueDroppedEvents);
        Count(w, c.Collector.SourceLostEvents); Count(w, c.Collector.PersistedEvents); Count(w, c.Collector.PersistedBlocks); Count(w, c.Collector.UnpersistedEvents);
        Required(c.Cache); EnumField(w, c.Cache.Outcome); Time(w, c.Cache.CheckedUtc);
        if (c.Cache.Outcome == CacheAuditOutcome.Verified && c.Cache.Snapshot is null) Invalid("A verified cache needs a snapshot.");
        if (c.Cache.Outcome != CacheAuditOutcome.Verified && c.Cache.Snapshot is not null) Invalid("A failed cache audit cannot assert a verified snapshot.");
        w.Write(c.Cache.Snapshot is not null);
        if (c.Cache.Snapshot is { } status)
        {
            Checkpoint(w, status.Checkpoint, c.NodeId, c.LedgerId);
            Count(w, status.PendingBlocks); Count(w, status.PendingPayloadBytes); Count(w, status.StoredPayloadBytes);
            if (status.PendingBlocks > status.Checkpoint.SequenceNumber || status.PendingPayloadBytes > status.StoredPayloadBytes)
                Invalid("Inconsistent cache counters.");
        }
    });
    public static byte[] Encode(AuditResultContent c) => Write("Result", w =>
    {
        Required(c); Identity(w, c.Version, c.NodeId, c.LedgerId, c.Algorithm, c.KeyId);
        Id(w, c.CollectorRunId); Id(w, c.ChallengeId); HashField(w, c.ChallengeHash); HashField(w, c.ResponseHash);
        if (c.AuditSequenceNumber < 1) Invalid("Invalid audit sequence.");
        w.Write(c.AuditSequenceNumber); HashField(w, c.PreviousResultHash); Time(w, c.AcceptedUtc); Findings(w, c.Findings);
        Count(w, c.NewQueueDroppedEvents); Count(w, c.NewSourceLostEvents);
        Required(c.Policy); Text(w, c.Policy.Version, 128); Count(w, c.Policy.ClockSkewWarningMilliseconds);
        if (c.Policy.BacklogWarningBlocks < 1 || c.Policy.BacklogWarningBytes < 1) Invalid("Invalid audit policy thresholds.");
        Count(w, c.Policy.BacklogWarningBlocks); Count(w, c.Policy.BacklogWarningBytes);
    });
    public static byte[] Encode(HealthQueryContent c) => Write("HealthQuery", w =>
    {
        Required(c); Identity(w, c.Version, c.NodeId, c.LedgerId, c.Algorithm, c.KeyId);
        Id(w, c.QueryId); Time(w, c.RequestedUtc);
    });
    public static byte[] Encode(NodeHealthContent c) => Write("NodeHealth", w =>
    {
        Required(c); Identity(w, c.Version, c.NodeId, c.LedgerId, c.Algorithm, c.KeyId);
        HashField(w, c.QueryHash); Time(w, c.GeneratedUtc);
        bool hasAudit = c.LastAcceptedAuditUtc.HasValue;
        if (hasAudit != c.LastAuditSequenceNumber.HasValue || hasAudit != (c.LastResultHash is not null)) Invalid("Incomplete audit history reference.");
        w.Write(hasAudit);
        if (hasAudit)
        {
            Time(w, c.LastAcceptedAuditUtc!.Value);
            if (c.LastAuditSequenceNumber < 1) Invalid("Invalid audit sequence.");
            w.Write(c.LastAuditSequenceNumber!.Value); HashField(w, c.LastResultHash!);
        }
        Required(c.Assessment); Text(w, c.Assessment.PolicyVersion, 128);
        if (c.Assessment.StaleAfterMilliseconds < 1 || c.Assessment.OfflineAfterMilliseconds <= c.Assessment.StaleAfterMilliseconds)
            Invalid("Invalid health freshness thresholds.");
        Count(w, c.Assessment.StaleAfterMilliseconds); Count(w, c.Assessment.OfflineAfterMilliseconds); EnumField(w, c.Assessment.State);
        w.Write(c.Assessment.Score.HasValue);
        if (c.Assessment.Score is { } score)
        {
            if (score is < 0 or > 100) Invalid("Invalid health score.");
            w.Write(score);
        }
        if (c.Assessment.Score.HasValue == (c.Assessment.State == ServerHealthState.Unknown)) Invalid("Unknown health must have no numeric score.");
        Findings(w, c.Assessment.Findings);
    });

    public static bool Verify(SignedAuditRequest x, ISignatureVerifier v) => x?.Content is { } c && Verify(() => Encode(c), c.Algorithm, c.KeyId, x.Signature, v);
    public static bool Verify(SignedAuditChallenge x, ISignatureVerifier v) => x?.Content is { } c && Verify(() => Encode(c), c.Algorithm, c.KeyId, x.Signature, v);
    public static bool Verify(SignedAuditResponse x, ISignatureVerifier v) => x?.Content is { } c && Verify(() => Encode(c), c.Algorithm, c.KeyId, x.Signature, v);
    public static bool Verify(SignedAuditResult x, ISignatureVerifier v) => x?.Content is { } c && Verify(() => Encode(c), c.Algorithm, c.KeyId, x.Signature, v);
    public static bool Verify(SignedHealthQuery x, ISignatureVerifier v) => x?.Content is { } c && Verify(() => Encode(c), c.Algorithm, c.KeyId, x.Signature, v);
    public static bool Verify(SignedNodeHealth x, ISignatureVerifier v) => x?.Content is { } c && Verify(() => Encode(c), c.Algorithm, c.KeyId, x.Signature, v);

    public static void Bind(SignedAuditChallenge challenge, SignedAuditRequest request)
    {
        var c = challenge.Content; var r = request.Content;
        if (c.NodeId != r.NodeId || c.LedgerId != r.LedgerId || c.RequestId != r.RequestId || c.CollectorRunId != r.CollectorRunId
            || c.RequestHash != Hash(Encode(r))) Invalid("The challenge does not match its signed request.");
    }
    public static void Bind(SignedAuditResponse response, SignedAuditChallenge challenge)
    {
        var r = response.Content; var c = challenge.Content;
        if (r.NodeId != c.NodeId || r.LedgerId != c.LedgerId || r.CollectorRunId != c.CollectorRunId || r.ChallengeId != c.ChallengeId
            || r.ChallengeHash != Hash(Encode(c)) || !CryptographicOperations.FixedTimeEquals(r.Nonce, c.Nonce))
            Invalid("The response does not match its challenge and nonce.");
    }
    public static void Bind(SignedAuditResult result, SignedAuditResponse response)
    {
        var a = result.Content; var r = response.Content;
        if (a.NodeId != r.NodeId || a.LedgerId != r.LedgerId || a.CollectorRunId != r.CollectorRunId || a.ChallengeId != r.ChallengeId
            || a.ChallengeHash != r.ChallengeHash || a.ResponseHash != Hash(Encode(r))) Invalid("The result does not identify its signed response.");
    }
    public static void Bind(SignedNodeHealth health, SignedHealthQuery query)
    {
        if (health.Content.NodeId != query.Content.NodeId || health.Content.LedgerId != query.Content.LedgerId
            || health.Content.QueryHash != Hash(Encode(query.Content))) Invalid("The health result does not match its query.");
    }
    public static AuditFinding[] Normalize(IEnumerable<AuditFinding> findings) => findings.Distinct().Order().ToArray();

    private static bool Verify(Func<byte[]> encode, string algorithm, string keyId, byte[] signature, ISignatureVerifier verifier)
    {
        if (signature is not { Length: > 0 and <= 65536 }) return false;
        try { return verifier.Verify(algorithm, keyId, encode(), signature); }
        catch (InvalidDataException) { return false; }
    }
    private static byte[] Write(string domain, Action<BinaryWriter> fields)
    {
        using var stream = new MemoryStream(); using var w = new BinaryWriter(stream, Utf8, leaveOpen: true);
        w.Write("Mrbr.Bastion.HeartbeatAudit." + domain + ".v1"); fields(w); w.Flush(); return stream.ToArray();
    }
    private static void Identity(BinaryWriter w, int version, string node, Guid ledger, string algorithm, string key)
    {
        if (version != Version) Invalid("Unsupported audit protocol version.");
        w.Write(version); Text(w, node, 256); Id(w, ledger); Text(w, algorithm, 128); Text(w, key, 256);
    }
    private static void Checkpoint(BinaryWriter w, LedgerCheckpoint c, string node, Guid ledger)
    {
        Required(c);
        if (c.NodeId != node || c.LedgerId != ledger || c.SequenceNumber < 0 || (c.SequenceNumber == 0 && c.BlockHash != GenesisHash)) Invalid("Invalid audit checkpoint.");
        Text(w, c.NodeId, 256); Id(w, c.LedgerId); Count(w, c.SequenceNumber); HashField(w, c.BlockHash);
    }
    private static void Findings(BinaryWriter w, AuditFinding[] findings)
    {
        if (findings is null || findings.Length > 32 || !findings.SequenceEqual(Normalize(findings))) Invalid("Findings must be unique and sorted.");
        w.Write(findings!.Length); foreach (var f in findings) EnumField(w, f);
    }
    private static void Text(BinaryWriter w, string text, int max)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > max) Invalid("Invalid audit metadata.");
        try { _ = Utf8.GetByteCount(text); }
        catch (EncoderFallbackException e) { throw new InvalidDataException("Audit metadata must be valid Unicode.", e); }
        w.Write(text);
    }
    private static void HashField(BinaryWriter w, string hash)
    {
        if (hash is not { Length: 64 } || hash.Any(c => !char.IsAsciiHexDigit(c)) || hash != hash.ToUpperInvariant()) Invalid("Invalid SHA-256 hash.");
        w.Write(Convert.FromHexString(hash));
    }
    private static void Id(BinaryWriter w, Guid id) { if (id == Guid.Empty) Invalid("An audit identifier is empty."); w.Write(id.ToByteArray()); }
    private static void Nonce(BinaryWriter w, byte[] nonce) { if (nonce is not { Length: 32 }) Invalid("An audit nonce must contain 32 bytes."); w.Write(nonce); }
    private static void Time(BinaryWriter w, DateTimeOffset time) { if (time == default || time.Offset != TimeSpan.Zero) Invalid("Audit times must be nondefault UTC values."); w.Write(time.UtcTicks); }
    private static void Count(BinaryWriter w, long value) { if (value < 0) Invalid("Audit counters must be nonnegative."); w.Write(value); }
    private static void EnumField<T>(BinaryWriter w, T value) where T : struct, Enum { if (!Enum.IsDefined(value)) Invalid("Invalid audit enum value."); w.Write(Convert.ToInt32(value)); }
    private static void Required(object? value) { if (value is null) Invalid("Missing audit fields."); }
    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Invalid(string message) => throw new InvalidDataException(message);
}
