using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Cryptography;

public sealed record TrustedSignatureKey(string Algorithm, string KeyId, ISignatureVerifier Verifier);

/// <summary>An explicit allowlist. Key IDs never trigger external lookups. Providers are owned by the caller.</summary>
public sealed class SignatureVerifierSet : ISignatureVerifier
{
    private readonly Dictionary<(string Algorithm, string KeyId), ISignatureVerifier> _keys = new();
    public SignatureVerifierSet(IEnumerable<TrustedSignatureKey> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        foreach (var key in keys)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(key.Algorithm);
            ArgumentException.ThrowIfNullOrWhiteSpace(key.KeyId);
            ArgumentNullException.ThrowIfNull(key.Verifier);
            if (!_keys.TryAdd((key.Algorithm, key.KeyId), key.Verifier)) throw new ArgumentException("Duplicate verification key.", nameof(keys));
        }
        if (_keys.Count == 0) throw new ArgumentException("At least one trusted key is required.", nameof(keys));
    }
    public bool Verify(string algorithm, string keyId, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
        algorithm is not null && keyId is not null && _keys.TryGetValue((algorithm, keyId), out var key) && key.Verify(algorithm, keyId, data, signature);
}
