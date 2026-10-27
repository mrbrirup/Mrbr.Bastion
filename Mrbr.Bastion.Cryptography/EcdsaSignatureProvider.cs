using System.Security.Cryptography;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Cryptography;

/// <summary>A BCL-backed P-256 provider. Public-only keys can verify receipts or historical blocks.</summary>
public sealed class EcdsaSignatureProvider : ISignatureSigner, ISignatureVerifier, IDisposable
{
    private readonly ECDsa _key;
    private readonly bool _ownsKey;
    private readonly object _gate = new();
    private bool _disposed;

    public EcdsaSignatureProvider(ECDsa key, string keyId, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (keyId.Length > 256) throw new ArgumentOutOfRangeException(nameof(keyId));
        if (key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            throw new ArgumentException("The key must use the NIST P-256 curve.", nameof(key));
        _key = key;
        KeyId = keyId;
        _ownsKey = ownsKey;
    }

    public static string Fingerprint(ECDsa key) => Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));

    public string Algorithm => "ECDSA-P256-SHA256";
    public string KeyId { get; }

    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    public bool Verify(string algorithm, string keyId, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (algorithm != Algorithm || keyId != KeyId || signature.Length != 64) return false;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            try
            {
                return _key.VerifyData(data, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (CryptographicException) { return false; }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            if (_ownsKey) _key.Dispose();
        }
    }
}
