using System.Buffers;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mrbr.Bastion.Abstraction;

/// <summary>Bounded outer-envelope encoding. Payload bytes are preserved without parsing.</summary>
public static class TelemetryJson
{
    /// <summary>HTTP block limit including base64 and signature overhead.</summary>
    public const int MaximumBlockBytes = 8 * 1024 * 1024;
    /// <summary>Maximum encoded receipt size.</summary>
    public const int MaximumReceiptBytes = 128 * 1024;
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8
    };
    /// <summary>Serializes a block or receipt without altering signed payload bytes.</summary>
    public static byte[] Encode<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);
    /// <summary>Decodes a bounded outer envelope without parsing its telemetry payload.</summary>
    public static T Decode<T>(ReadOnlySpan<byte> bytes, int maximumBytes)
    {
        if (bytes.Length > maximumBytes) throw new TelemetryMessageTooLargeException();
        try { return JsonSerializer.Deserialize<T>(bytes, Options) ?? throw new InvalidDataException("A telemetry envelope cannot be null."); }
        catch (JsonException error) { throw new InvalidDataException("Malformed telemetry envelope.", error); }
    }
    /// <summary>Bounds the entire envelope before JSON deserialization.</summary>
    public static async Task<T> ReadAsync<T>(Stream stream, int maximumBytes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);
        using var buffer = new MemoryStream();
        byte[] chunk = ArrayPool<byte>.Shared.Rent(16384);
        try
        {
            while (true)
            {
                int count = await stream.ReadAsync(chunk.AsMemory(0, (int)Math.Min(chunk.Length, (long)maximumBytes - buffer.Length + 1)), cancellationToken).ConfigureAwait(false);
                if (count == 0) break;
                if (buffer.Length + count > maximumBytes) throw new TelemetryMessageTooLargeException();
                buffer.Write(chunk, 0, count);
            }
            return Decode<T>(buffer.GetBuffer().AsSpan(0, (int)buffer.Length), maximumBytes);
        }
        finally { ArrayPool<byte>.Shared.Return(chunk); }
    }
}

/// <summary>An encoded envelope exceeded its limit before deserialization.</summary>
public sealed class TelemetryMessageTooLargeException : IOException
{
    /// <summary>Creates a bounded-read rejection.</summary>
    public TelemetryMessageTooLargeException() : base("The telemetry message exceeds the configured size limit.") { }
}
