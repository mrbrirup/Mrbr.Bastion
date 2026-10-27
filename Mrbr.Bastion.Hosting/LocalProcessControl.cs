using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;

namespace Mrbr.Bastion.Hosting;

/// <summary>Optional, authenticated current-user-only control channel for desktop-managed processes.</summary>
public sealed class LocalProcessControl : IAsyncDisposable
{
    public const string PipeVariable = "BASTION_CONTROL_PIPE";
    public const string TokenVariable = "BASTION_CONTROL_TOKEN";
    public const string FileIoProcessesVariable = "BASTION_FILE_IO_PROCESSES";
    private const int MaximumPolicyBytes = 8192;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _listener;

    public static LocalProcessControl FromEnvironment(Action requestStop, Action<string>? updateFileIo = null) =>
        new(Environment.GetEnvironmentVariable(PipeVariable), Environment.GetEnvironmentVariable(TokenVariable), requestStop, updateFileIo);

    public LocalProcessControl(string? pipe, string? token, Action requestStop, Action<string>? updateFileIo = null)
    {
        ArgumentNullException.ThrowIfNull(requestStop);
        if (pipe is null && token is null) { _listener = Task.CompletedTask; return; }
        Validate(pipe, token);
        _listener = ListenAsync(pipe!, token!, requestStop, updateFileIo, _stop.Token);
    }

    private static void Validate(string? pipe, string? token)
    {
        if (pipe is not { Length: > 0 and <= 100 } || pipe.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')
            || token is not { Length: 64 } || token.Any(c => !char.IsAsciiHexDigit(c)))
            throw new ArgumentException("Invalid local process control identity.");
    }

    private static async Task ListenAsync(string pipe, string token, Action requestStop, Action<string>? updateFileIo, CancellationToken ct)
    {
        byte[] expected = Encoding.ASCII.GetBytes("STOP " + token);
        byte[] expectedPolicy = Encoding.ASCII.GetBytes("FILE " + token);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                using var server = new NamedPipeServerStream(pipe, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attempt.CancelAfter(TimeSpan.FromSeconds(3));
                try
                {
                    byte[] message = new byte[expected.Length];
                    await server.ReadExactlyAsync(message, attempt.Token).ConfigureAwait(false);
                    bool shutdown = CryptographicOperations.FixedTimeEquals(message, expected);
                    if (!shutdown)
                    {
                        if (updateFileIo is null || !CryptographicOperations.FixedTimeEquals(message, expectedPolicy)) continue;
                        byte[] length = new byte[4];
                        await server.ReadExactlyAsync(length, attempt.Token).ConfigureAwait(false);
                        int size = BinaryPrimitives.ReadInt32LittleEndian(length);
                        if (size is < 1 or > MaximumPolicyBytes) continue;
                        byte[] payload = new byte[size];
                        await server.ReadExactlyAsync(payload, attempt.Token).ConfigureAwait(false);
                        updateFileIo(new UTF8Encoding(false, true).GetString(payload));
                    }
                    await server.WriteAsync("OK"u8.ToArray(), attempt.Token).ConfigureAwait(false);
                    await server.FlushAsync(attempt.Token).ConfigureAwait(false);
                    if (shutdown) { requestStop(); return; }
                }
                catch (IOException) { }
                catch (ArgumentException) { }
                catch (System.Text.Json.JsonException) { }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }

    public static async Task RequestStopAsync(string pipe, string token, CancellationToken cancellationToken = default)
        => await RequestAsync(pipe, token, null, cancellationToken).ConfigureAwait(false);

    public static async Task UpdateFileIoAsync(string pipe, string token, string policy, CancellationToken cancellationToken = default)
        => await RequestAsync(pipe, token, policy, cancellationToken).ConfigureAwait(false);

    private static async Task RequestAsync(string pipe, string token, string? policy, CancellationToken cancellationToken)
    {
        Validate(pipe, token);
        byte[]? payload = policy is null ? null : Encoding.UTF8.GetBytes(policy);
        if (payload is { Length: < 1 or > MaximumPolicyBytes }) throw new ArgumentException("Invalid process policy length.", nameof(policy));
        using var client = new NamedPipeClientStream(".", pipe, PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
        await client.WriteAsync(Encoding.ASCII.GetBytes((policy is null ? "STOP " : "FILE ") + token), cancellationToken).ConfigureAwait(false);
        if (payload is not null)
        {
            byte[] length = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(length, payload.Length);
            await client.WriteAsync(length, cancellationToken).ConfigureAwait(false);
            await client.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        await client.FlushAsync(cancellationToken).ConfigureAwait(false);
        byte[] reply = new byte[2];
        await client.ReadExactlyAsync(reply, cancellationToken).ConfigureAwait(false);
        if (!reply.AsSpan().SequenceEqual("OK"u8)) throw new IOException("Control request was not acknowledged.");
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        try { await _listener.ConfigureAwait(false); }
        finally { _stop.Dispose(); }
    }
}
