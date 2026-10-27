using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Ingestion;
using Mrbr.Bastion.Ingestion.Sqlite;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class IngestionTests
{
    [Fact]
    public async Task ExistingCentralStoreGainsCoveringCapacityIndexAndRetainsOriginalReceipt()
    {
        await using var f = await IngestionFixture.CreateAsync();
        var original = await f.Service.IngestAsync(f.First);
        await f.Store.DisposeAsync();
        using (var db = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = f.Options.DatabasePath, Pooling = false }.ToString()))
        {
            db.Open(); using var drop = db.CreateCommand();
            drop.CommandText = "DROP INDEX ingested_blocks_payload_size"; drop.ExecuteNonQuery();
        }
        await f.ReopenStoreAsync();
        var repeated = await f.Service.IngestAsync(f.First);
        Assert.Equal(original.Content, repeated.Content); Assert.Equal(original.Signature, repeated.Signature);
        using var readerDb = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = f.Options.DatabasePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        readerDb.Open(); using var explain = readerDb.CreateCommand();
        explain.CommandText = "EXPLAIN QUERY PLAN " + SqliteIngestionStore.StoredBytesSql;
        using var rows = explain.ExecuteReader(); Assert.True(rows.Read());
        Assert.Contains("USING COVERING INDEX ingested_blocks_payload_size", rows.GetString(3));
    }

    [Fact]
    public async Task DurableCentralCommitReturnsAReceiptThatSettlesTheOutbox()
    {
        await using var f = await IngestionFixture.CreateAsync();
        var receipt = await f.Service.IngestAsync(f.First);
        await f.Cache.ReconcileAsync(receipt);
        Assert.Empty(await f.Cache.ReadPendingAsync());
        await f.ReopenStoreAsync();
        var stored = await f.Store.ReadAsync(f.First.Content.NodeId, f.First.Content.LedgerId, 1);
        Assert.NotNull(stored);
        Assert.Equal(f.First.Content.Payload, stored.Block.Content.Payload);
        Assert.Equal(receipt.Signature, stored.Receipt.Signature);
        Assert.Equal(1, (await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId))!.SequenceNumber);
    }
    [Fact]
    public async Task RestartedReceiverReturnsOriginalReceiptWithoutCallingTheSigner()
    {
        await using var f = await IngestionFixture.CreateAsync();
        var original = await f.Service.IngestAsync(f.First);
        var second = await f.Cache.AppendAsync([TestLedger.Event()]);
        await f.Service.IngestAsync(second);
        await f.ReopenStoreAsync();
        var signer = new FailingSigner(f.Local.Server) { ShouldFail = true };
        var service = new TelemetryIngestionService(f.Trust, f.Store, signer, f.Local.Server);
        var repeated = await service.IngestAsync(f.First);
        Assert.Equal(original.Content, repeated.Content);
        Assert.Equal(original.Signature, repeated.Signature);
    }
    [Fact]
    public async Task ConcurrentDuplicateSubmissionsHaveOneStoredReceipt()
    {
        await using var f = await IngestionFixture.CreateAsync();
        var receipts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => f.Service.IngestAsync(f.First))));
        Assert.All(receipts, item => Assert.Equal(receipts[0].Signature, item.Signature));
        await f.Store.VerifyIntegrityAsync();
    }
    [Theory]
    [InlineData("payload")]
    [InlineData("node")]
    [InlineData("ledger")]
    [InlineData("key")]
    public async Task TamperingOrUnenrolledIdentityCannotCreateAReceipt(string changed)
    {
        await using var f = await IngestionFixture.CreateAsync();
        var c = f.First.Content;
        c = changed switch
        {
            "node" => c with { NodeId = "unregistered" },
            "ledger" => c with { LedgerId = Guid.NewGuid() },
            "key" => c with { KeyId = "unknown" },
            _ => c with { Payload = LedgerProtocol.SerializeEvents([TestLedger.Event(999)]) }
        };
        var block = changed == "payload" ? f.First with { Content = c } : f.Sign(c);
        var error = await Assert.ThrowsAsync<TelemetryRejectedException>(() => f.Service.IngestAsync(block));
        Assert.Equal(IngestionFailure.UntrustedBlock, error.Failure);
        Assert.Null(await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId));
    }
    [Fact]
    public async Task ANodeCannotUseItsKeyToImpersonateAnotherEnrolledNode()
    {
        await using var f = await IngestionFixture.CreateAsync();
        var trust = new StaticNodeTrustStore([new("other-node", f.First.Content.LedgerId, f.Local.Server)]);
        var service = new TelemetryIngestionService(trust, f.Store, f.Local.Server, f.Local.Server);
        var forged = f.Sign(f.First.Content with { NodeId = "other-node", KeyId = f.Local.Server.KeyId });
        Assert.Equal(IngestionFailure.UntrustedBlock, (await Assert.ThrowsAsync<TelemetryRejectedException>(() => service.IngestAsync(forged))).Failure);
    }
    [Fact]
    public async Task AuthenticatedMalformedPayloadIsRejectedBeforeStorage()
    {
        await using var f = await IngestionFixture.CreateAsync();
        var block = f.Sign(f.First.Content with { Payload = [0, 1, 2] });
        Assert.Equal(IngestionFailure.InvalidBlock, (await Assert.ThrowsAsync<TelemetryRejectedException>(() => f.Service.IngestAsync(block))).Failure);
        Assert.Null(await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId));
    }
    [Fact]
    public async Task SequenceGapCanBeRetriedAfterItsPredecessorArrives()
    {
        await using var f = await IngestionFixture.CreateAsync();
        var second = await f.Cache.AppendAsync([TestLedger.Event()]);
        Assert.Equal(IngestionFailure.SequenceConflict, (await Assert.ThrowsAsync<TelemetryRejectedException>(() => f.Service.IngestAsync(second))).Failure);
        await f.Service.IngestAsync(f.First);
        await f.Service.IngestAsync(second);
        await f.Store.VerifyIntegrityAsync();
    }
    [Theory]
    [InlineData("previous", IngestionFailure.ChainConflict)]
    [InlineData("sequence", IngestionFailure.SequenceConflict)]
    [InlineData("block-id", IngestionFailure.SequenceConflict)]
    public async Task ValidlySignedForksAndConflictingIdsAreRejected(string changed, IngestionFailure expected)
    {
        await using var f = await IngestionFixture.CreateAsync();
        await f.Service.IngestAsync(f.First);
        var second = await f.Cache.AppendAsync([TestLedger.Event()]);
        var c = changed switch
        {
            "previous" => second.Content with { PreviousBlockHash = new string('A', 64) },
            "sequence" => f.First.Content with { BlockId = Guid.NewGuid() },
            _ => second.Content with { BlockId = f.First.Content.BlockId }
        };
        Assert.Equal(expected, (await Assert.ThrowsAsync<TelemetryRejectedException>(() => f.Service.IngestAsync(f.Sign(c)))).Failure);
        Assert.Null(await f.Store.ReadAsync(c.NodeId, c.LedgerId, 2));
    }
    [Fact]
    public async Task SigningFailureRollsBackBlockAndTipAndLeavesLocalEvidencePending()
    {
        await using var f = await IngestionFixture.CreateAsync();
        var signer = new FailingSigner(f.Local.Server) { ShouldFail = true };
        var service = new TelemetryIngestionService(f.Trust, f.Store, signer, f.Local.Server);
        await Assert.ThrowsAsync<IOException>(() => service.IngestAsync(f.First));
        Assert.Null(await f.Store.ReadAsync(f.First.Content.NodeId, f.First.Content.LedgerId, 1));
        Assert.Null(await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId));
        Assert.Single(await f.Cache.ReadPendingAsync());
        signer.ShouldFail = false;
        await service.IngestAsync(f.First);
    }
    [Fact]
    public async Task CapacityExhaustionNeverReturnsProofForAnUnstoredBlock()
    {
        await using var f = await IngestionFixture.CreateAsync();
        int size = f.First.Content.Payload.Length;
        await f.ReopenStoreAsync(f.Options with { MaximumStoredPayloadBytes = size, BlockLimits = new() { MaximumPayloadBytes = size } });
        await f.Service.IngestAsync(f.First);
        var second = f.Sign(f.First.Content with { SequenceNumber = 2, BlockId = Guid.NewGuid(), PreviousBlockHash = f.First.BlockHash });
        Assert.Equal(IngestionFailure.CapacityExceeded, (await Assert.ThrowsAsync<TelemetryRejectedException>(() => f.Service.IngestAsync(second))).Failure);
        Assert.Null(await f.Store.ReadAsync(second.Content.NodeId, second.Content.LedgerId, 2));
    }
    [Theory]
    [InlineData("UPDATE ingested_blocks SET receipt=x'7B7D'")]
    [InlineData("UPDATE ledgers SET last_sequence=8")]
    [InlineData("UPDATE ingested_blocks SET body=x'00'")]
    public async Task StartupRejectsCorruptedCentralEvidence(string sql)
    {
        await using var f = await IngestionFixture.CreateAsync();
        await f.Service.IngestAsync(f.First);
        await f.Store.DisposeAsync();
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.Options.DatabasePath, Pooling = false }.ToString()))
        {
            connection.Open(); using var command = connection.CreateCommand(); command.CommandText = sql; command.ExecuteNonQuery();
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => f.ReopenStoreAsync());
    }
    [Fact]
    public async Task SeparateEnrolledNodesMaintainIndependentContiguousLedgers()
    {
        await using var f = await IngestionFixture.CreateAsync();
        using var otherKey = new Mrbr.Bastion.Cryptography.EcdsaSignatureProvider(ECDsa.Create(ECCurve.NamedCurves.nistP256), "other-key", ownsKey: true);
        await using var otherCache = await Mrbr.Bastion.Cache.DurableTelemetryCache.OpenAsync(f.Local.Options with
        { NodeId = "second-node", DatabasePath = Path.Combine(f.Local.DirectoryPath, "second-outbox.db") }, otherKey, otherKey, f.Local.Server);
        var otherBlock = await otherCache.AppendAsync([TestLedger.Event()]);
        var trust = new StaticNodeTrustStore([
            new(f.First.Content.NodeId, f.First.Content.LedgerId, f.Local.Node),
            new(otherBlock.Content.NodeId, otherBlock.Content.LedgerId, otherKey)]);
        await f.Store.DisposeAsync();
        await using var store = await Mrbr.Bastion.Ingestion.Sqlite.SqliteIngestionStore.OpenAsync(f.Options, trust, f.Local.Server);
        var service = new TelemetryIngestionService(trust, store, f.Local.Server, f.Local.Server);
        await service.IngestAsync(f.First);
        var receipt = await service.IngestAsync(otherBlock);
        await otherCache.ReconcileAsync(receipt);
        Assert.Equal(1, (await store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId))!.SequenceNumber);
        Assert.Equal(1, (await store.GetCheckpointAsync(otherBlock.Content.NodeId, otherBlock.Content.LedgerId))!.SequenceNumber);
        await store.VerifyIntegrityAsync();
    }

    [Fact]
    public async Task DeletingActiveTipEvidencePreventsIssuingAnotherReceipt()
    {
        await using var f = await IngestionFixture.CreateAsync();
        await f.Service.IngestAsync(f.First);
        var second = await f.Cache.AppendAsync([TestLedger.Event()]);
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.Options.DatabasePath, Pooling = false }.ToString()))
        {
            connection.Open(); using var command = connection.CreateCommand(); command.CommandText = "DELETE FROM ingested_blocks"; command.ExecuteNonQuery();
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Service.IngestAsync(second));
        Assert.Equal(2, (await f.Cache.ReadPendingAsync()).Count);
    }

    [Fact]
    public async Task AbruptReceiverDeathRetainsItsCommittedBlockAndReceipt()
    {
        await using var f = await IngestionFixture.CreateAsync();
        await f.Store.DisposeAsync();
        string blockPath = Path.Combine(f.Local.DirectoryPath, "test-block.json");
        string nodeKeyPath = Path.Combine(f.Local.DirectoryPath, "test-node-public.pem");
        string serverKeyPath = Path.Combine(f.Local.DirectoryPath, "test-receiver-private.pem");
        File.WriteAllBytes(blockPath, TelemetryJson.Encode(f.First));
        File.WriteAllText(nodeKeyPath, f.Local.NodeKey.ExportSubjectPublicKeyInfoPem());
        File.WriteAllText(serverKeyPath, f.Local.ServerKey.ExportPkcs8PrivateKeyPem());
        using var child = RecoveryAndEtwTests.StartProbe("--ingestion", f.Options.DatabasePath, blockPath, nodeKeyPath, serverKeyPath);
        try { Assert.Equal("READY", await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15))); }
        finally
        {
            if (!child.HasExited) child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        }
        await TestLedger.AfterProcessExitAsync(()=>f.ReopenStoreAsync());
        var stored = await f.Store.ReadAsync(f.First.Content.NodeId, f.First.Content.LedgerId, 1);
        Assert.NotNull(stored);
        Assert.Equal(f.First.BlockHash, stored.Block.BlockHash);
        var retry = await f.Service.IngestAsync(f.First);
        Assert.Equal(stored.Receipt.Signature, retry.Signature);
        await f.Cache.ReconcileAsync(retry);
        Assert.Empty(await f.Cache.ReadPendingAsync());
    }

    [Fact]
    public async Task CanceledIngestionDoesNotCommit()
    {
        await using var f = await IngestionFixture.CreateAsync();
        using var stop = new CancellationTokenSource(); stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Service.IngestAsync(f.First, stop.Token));
        Assert.Null(await f.Store.GetCheckpointAsync(f.First.Content.NodeId, f.First.Content.LedgerId));
    }
}
