using System.Buffers.Binary;

namespace Mrbr.Bastion.Core;

/// <summary>Allocation-free, single-dispatch-thread identities: one random run prefix, then a counter.</summary>
internal sealed class EventIdSequence
{
    private readonly Guid _run;
    private ulong _sequence;
    public EventIdSequence(Guid run)
    {
        Span<byte> bytes = stackalloc byte[16]; run.TryWriteBytes(bytes);
        if (BinaryPrimitives.ReadUInt64LittleEndian(bytes) == 0) throw new ArgumentException("A nonzero run prefix is required.", nameof(run));
        _run = run;
    }
    public Guid Next()
    {
        Span<byte> bytes = stackalloc byte[16]; _run.TryWriteBytes(bytes);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[8..], BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]) ^ checked(++_sequence));
        return new Guid(bytes);
    }
}
