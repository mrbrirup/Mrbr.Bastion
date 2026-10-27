using System.Security.Cryptography;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Cache;

/// <summary>Compatibility facade. New applications can reference Mrbr.Bastion.Cryptography directly.</summary>
public sealed class EcdsaSignatureProvider : ISignatureSigner, ISignatureVerifier, IDisposable
{
    private readonly Cryptography.EcdsaSignatureProvider _provider;
    public EcdsaSignatureProvider(ECDsa key, string keyId, bool ownsKey = false) => _provider = new(key, keyId, ownsKey);
    public string Algorithm => _provider.Algorithm;
    public string KeyId => _provider.KeyId;
    public byte[] Sign(ReadOnlySpan<byte> data) => _provider.Sign(data);
    public bool Verify(string algorithm, string keyId, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => _provider.Verify(algorithm, keyId, data, signature);
    public void Dispose() => _provider.Dispose();
}
