namespace Mrbr.Bastion.Abstraction;

/// <summary>Delivers a signed block and returns a verified receipt for that exact block.</summary>
public interface ITelemetryTransport
{
    /// <summary>Does not settle local data. Retrying the same block must be safe.</summary>
    Task<SettlementReceipt> SubmitAsync(SignedTelemetryBlock block, CancellationToken cancellationToken = default);
}

/// <summary>A delivery failure with an explicit retry classification.</summary>
public sealed class TelemetryTransportException : Exception
{
    /// <summary>Creates a delivery failure without exposing remote response bodies.</summary>
    public TelemetryTransportException(string message, bool isTransient, Exception? innerException = null)
        : base(message, innerException) => IsTransient = isTransient;
    /// <summary>True for temporary connectivity, timeout, throttling, or availability failures.</summary>
    public bool IsTransient { get; }
}
