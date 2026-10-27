using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Cache;

namespace Mrbr.Bastion.Tests;

internal sealed class TestLedger : IDisposable
{
    public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), "Mrbr.Bastion.Tests", Guid.NewGuid().ToString("N"));
    public ECDsa NodeKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public EcdsaSignatureProvider Node { get; }
    public ECDsa ServerKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public EcdsaSignatureProvider Server { get; }
    public DurableCacheOptions Options => new() { DatabasePath = Path.Combine(DirectoryPath, "cache.db"), NodeId = "test-node" };

    public TestLedger() { Node = new(NodeKey, "node-key"); Server = new(ServerKey, "server-key"); }

    public Task<DurableTelemetryCache> OpenAsync(LedgerCheckpoint? checkpoint = null) =>
        DurableTelemetryCache.OpenAsync(Options, Node, Node, Server, checkpoint);

    // Opt in only after a test child has terminated; an ordinary second writer must still fail immediately.
    public static async Task<T> AfterProcessExitAsync<T>(Func<Task<T>> reopen)
    {
        for(int attempt=0;;attempt++)
        {
            try{return await reopen();}
            catch(IOException error)when(OperatingSystem.IsWindows() && ((error.HResult & 0xffff) is 32 or 33) && attempt<40)
            {await Task.Delay(50);}
            // A terminated Windows child can leave a mapped WAL SHM view briefly
            // alive. SQLite may report IOERR_TRUNCATE or IOERR_SHMOPEN while
            // opening that view, rather than a managed sharing violation.
            // Retry only here, after exit, within the same two-second bound.
            // Other I/O/corruption errors and ordinary writer opens still fail.
            catch(SqliteException error)when(OperatingSystem.IsWindows()
                && error.SqliteExtendedErrorCode is 1546 or 4618 && attempt<40)
            {await Task.Delay(50);}
            catch(SqliteException error)
            {throw new InvalidOperationException($"Post-exit SQLite reopen failed (primary {error.SqliteErrorCode}, extended {error.SqliteExtendedErrorCode}).",error);}
        }
    }
    public static async Task AfterProcessExitAsync(Func<Task> reopen) =>
        _ = await AfterProcessExitAsync(async()=>{await reopen();return true;});

    public SettlementReceipt Receipt(SignedTelemetryBlock block)
    {
        var content = new SettlementReceiptContent(1, block.Content.NodeId, block.Content.LedgerId,
            block.Content.BlockId, block.Content.SequenceNumber, block.BlockHash, DateTimeOffset.UtcNow, Server.Algorithm, Server.KeyId);
        return new SettlementReceipt(content, Server.Sign(LedgerProtocol.EncodeReceipt(content)));
    }

    public SettlementReceipt Sign(SettlementReceiptContent content) =>
        new(content, Server.Sign(LedgerProtocol.EncodeReceipt(content)));

    public void Execute(string sql, params (string Name, object Value)[] parameters)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Options.DatabasePath,
            Pooling = false
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var item in parameters) command.Parameters.AddWithValue(item.Name, item.Value);
        command.ExecuteNonQuery();
    }

    public static TelemetryEvent Event(int pid = 123, string? path = null) => new()
    {
        TimestampUtc = DateTimeOffset.UtcNow,
        Kind = path is null ? TelemetryEventKind.ProcessStarted : TelemetryEventKind.FileRead,
        ProcessId = pid,
        FilePath = path,
        Source = "test"
    };

    public void Dispose()
    {
        Node.Dispose();
        NodeKey.Dispose();
        Server.Dispose();
        ServerKey.Dispose();
        string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "Mrbr.Bastion.Tests")) + Path.DirectorySeparatorChar;
        string target = Path.GetFullPath(DirectoryPath);
        if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Test cleanup escaped its temporary root.");
        for (int attempt=0;;attempt++)
        {
            try { if (Directory.Exists(target)) Directory.Delete(target, recursive: true); break; }
            catch (IOException error) when (OperatingSystem.IsWindows() && ((error.HResult & 0xffff) is 32 or 33) && attempt<40)
            { Thread.Sleep(50); }
            // Windows can briefly return ACCESS_DENIED for a mapped SQLite SHM
            // file after a test child exits. Retry without changing its ACL or
            // attributes; a persistent permission error still fails cleanup.
            catch (UnauthorizedAccessException) when (OperatingSystem.IsWindows() && attempt<40)
            { Thread.Sleep(50); }
        }
    }
}

internal sealed class DelegateSource(Func<Action<TelemetryEvent>, CancellationToken, Task> run, long eventsLost = 0) : ITelemetrySource
{
    public long EventsLost => eventsLost;
    public Task RunAsync(Action<TelemetryEvent> onEvent, CancellationToken cancellationToken = default) => run(onEvent, cancellationToken);
}

internal sealed class FailingSigner(ISignatureSigner inner) : ISignatureSigner
{
    public bool ShouldFail { get; set; }
    public string Algorithm => inner.Algorithm;
    public string KeyId => inner.KeyId;
    public byte[] Sign(ReadOnlySpan<byte> data) => ShouldFail ? throw new IOException("Injected signing failure") : inner.Sign(data);
}
