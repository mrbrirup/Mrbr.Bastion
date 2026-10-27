namespace Mrbr.Bastion.Abstraction;

/// <summary>Signs canonical protocol bytes using a configured key. Implementations must be thread-safe.</summary>
public interface ISignatureSigner
{
    /// <summary>The allowlisted algorithm identifier included in signed metadata.</summary>
    string Algorithm { get; }
    /// <summary>The identifier of the signing key.</summary>
    string KeyId { get; }
    /// <summary>Creates a signature over the exact supplied bytes.</summary>
    byte[] Sign(ReadOnlySpan<byte> data);
}

/// <summary>Verifies against explicitly trusted algorithms and keys, including retained historical keys.</summary>
public interface ISignatureVerifier
{
    /// <summary>Returns false for an unknown algorithm, key, or invalid signature.</summary>
    bool Verify(string algorithm, string keyId, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
}
