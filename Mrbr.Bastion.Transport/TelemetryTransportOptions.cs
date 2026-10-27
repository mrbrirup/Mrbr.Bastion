namespace Mrbr.Bastion.Transport;

public sealed record TelemetryTransportOptions
{
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Development/test escape hatch. Non-loopback cleartext is always rejected.</summary>
    public bool AllowInsecureLoopback { get; init; }
    public void ValidateAddress(Uri address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!address.IsAbsoluteUri || address.UserInfo.Length != 0 || address.Query.Length != 0 || address.Fragment.Length != 0
            || (address.Scheme != "https" && !(AllowInsecureLoopback && address.Scheme == "http" && address.IsLoopback)))
            throw new ArgumentException("An HTTPS service URI without credentials, query, or fragment is required.", nameof(address));
        if (RequestTimeout <= TimeSpan.Zero || RequestTimeout > TimeSpan.FromMinutes(5)) throw new ArgumentOutOfRangeException(nameof(RequestTimeout));
    }
}
