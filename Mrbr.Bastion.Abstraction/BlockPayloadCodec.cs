namespace Mrbr.Bastion.Abstraction;

/// <summary>Opt-in validation of a signed payload. Implementations must bound decoding and verify record count.</summary>
public interface IBlockPayloadCodec
{
    /// <summary>The explicitly supported wire format.</summary>
    string Format { get; }
    /// <summary>Validates bounded payload contents and their declared record count.</summary>
    void Validate(ReadOnlyMemory<byte> payload, int recordCount);
}
/// <summary>Dispatches payload validation to an explicitly registered codec.</summary>
public static class BlockPayloadValidation
{
    /// <summary>Rejects malformed or unregistered payload formats.</summary>
    public static void Validate(SignedTelemetryBlock block, IEnumerable<IBlockPayloadCodec> codecs)
    {
        if (block.Content.PayloadFormat == LedgerProtocol.PayloadFormat) { _ = LedgerProtocol.DeserializeEvents(block); return; }
        var codec = codecs.SingleOrDefault(c => c.Format == block.Content.PayloadFormat)
            ?? throw new InvalidDataException("This payload format has not been enabled by this host.");
        codec.Validate(block.Content.Payload, block.Content.EventCount);
    }
}
