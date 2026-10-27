using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Cache;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class DurableCacheTests
{
    [Fact]
    public async Task FullAuditRetainsItsSnapshotWhileAppendsAndReceiptsContinue()
    {
        using var fixture = new TestLedger();
        using var verifier = new PausingVerifier(fixture.Node);
        await using var cache = await DurableTelemetryCache.OpenAsync(fixture.Options, fixture.Node, verifier, fixture.Server);
        var first = await cache.AppendAsync([TestLedger.Event()]);
        verifier.Arm();
        var auditing = Task.Run(() => cache.CaptureAuditSnapshotAsync());
        CacheStatus audit;
        SignedTelemetryBlock second;
        try
        {
            Assert.True(verifier.Entered.Wait(TimeSpan.FromSeconds(10)), "The full audit did not reach verification.");
            second = await cache.AppendAsync([TestLedger.Event()]).WaitAsync(TimeSpan.FromSeconds(5));
            await cache.ReconcileAsync(fixture.Receipt(first)).WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally { verifier.Resume.Set(); audit = await auditing.WaitAsync(TimeSpan.FromSeconds(15)); }
        Assert.Equal(1, audit.Checkpoint.SequenceNumber);
        Assert.Equal(first.BlockHash, audit.Checkpoint.BlockHash);
        Assert.Equal(1, audit.PendingBlocks); // Receipt was added after this snapshot began.
        var current = await cache.GetStatusAsync();
        Assert.Equal(second.BlockHash, current.Checkpoint.BlockHash);
        Assert.Equal(1, current.PendingBlocks);
        await cache.VerifyIntegrityAsync();
        Assert.Equal(3, (await cache.AppendAsync([TestLedger.Event()])).Content.SequenceNumber);
    }

    private sealed class PausingVerifier(ISignatureVerifier inner) : ISignatureVerifier, IDisposable
    {
        private int _armed;
        public ManualResetEventSlim Entered { get; } = new();
        public ManualResetEventSlim Resume { get; } = new();
        public void Arm() => Interlocked.Exchange(ref _armed, 1);
        public bool Verify(string algorithm, string keyId, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            if (Interlocked.Exchange(ref _armed, 0) == 1)
            {
                Entered.Set();
                if (!Resume.Wait(TimeSpan.FromSeconds(20))) throw new TimeoutException("Audit test was not resumed.");
            }
            return inner.Verify(algorithm, keyId, data, signature);
        }
        public void Dispose() { Resume.Set(); Entered.Dispose(); Resume.Dispose(); }
    }

    [Fact]
    public async Task ExistingOutboxGainsMetadataIndexesWithoutChangingEvidenceOrAccounting()
    {
        using var fixture = new TestLedger();
        SignedTelemetryBlock first, second;
        CacheStatus before;
        await using (var cache = await fixture.OpenAsync())
        {
            first = await cache.AppendAsync([TestLedger.Event(path: new string('x', 32000))]);
            second = await cache.AppendAsync([TestLedger.Event()]);
            await cache.ReconcileAsync(fixture.Receipt(first));
            before = await cache.GetStatusAsync();
        }
        // Simulate the original schema: signed blocks and receipts predate the derived indexes.
        fixture.Execute("DROP INDEX blocks_payload_size; DROP INDEX blocks_pending;");
        await using var reopened = await fixture.OpenAsync(before.Checkpoint);
        Assert.Equal(before, await reopened.GetStatusAsync());
        Assert.Equal(second.BlockHash, Assert.Single(await reopened.ReadPendingAsync()).BlockHash);
        await reopened.ReconcileAsync(fixture.Receipt(second));
        var status = await reopened.GetStatusAsync();
        Assert.Equal(0, status.PendingBlocks); Assert.Equal(0, status.PendingPayloadBytes);
        Assert.Equal(first.Content.Payload.Length + second.Content.Payload.Length, status.StoredPayloadBytes);
        await reopened.VerifyIntegrityAsync(before.Checkpoint);

        using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = fixture.Options.DatabasePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        db.Open();
        foreach (string sql in new[] { DurableTelemetryCache.StoredBytesSql, DurableTelemetryCache.StatusSql })
        {
            using var query = db.CreateCommand(); query.CommandText = "EXPLAIN QUERY PLAN " + sql;
            using var rows = query.ExecuteReader(); var plan = new List<string>();
            while (rows.Read()) plan.Add(rows.GetString(3));
            Assert.Contains(plan, detail => detail.Contains("blocks_payload_size", StringComparison.Ordinal));
            Assert.DoesNotContain(plan, detail => detail == "SCAN blocks");
            if (sql == DurableTelemetryCache.StatusSql)
                Assert.Equal(2, plan.Count(detail => detail.Contains("blocks_pending", StringComparison.Ordinal)));
        }
    }

    [Fact]
    public async Task RestartRecoversPendingPayloadSequenceAndChain()
    {
        using var fixture = new TestLedger();
        var item = TestLedger.Event(path: @"C:\sensitive\record.txt");
        SignedTelemetryBlock first;
        await using (var cache = await fixture.OpenAsync()) first = await cache.AppendAsync([item]);
        await using var reopened = await fixture.OpenAsync();
        var pending = await reopened.ReadPendingAsync();
        Assert.Single(pending);
        Assert.Equal(item, Assert.Single(LedgerProtocol.DeserializeEvents(pending[0])));
        var second = await reopened.AppendAsync([TestLedger.Event()]);
        Assert.Equal(2, second.Content.SequenceNumber);
        Assert.Equal(first.BlockHash, second.Content.PreviousBlockHash);
        Assert.Equal(first.Content.LedgerId, second.Content.LedgerId);
        await reopened.VerifyIntegrityAsync();
    }

    [Fact]
    public async Task ReceiptIsDurableIdempotentAndRetainsAuditHistory()
    {
        using var fixture = new TestLedger();
        LedgerCheckpoint checkpoint;
        await using (var cache = await fixture.OpenAsync())
        {
            var block = await cache.AppendAsync([TestLedger.Event()]);
            var receipt = fixture.Receipt(block);
            await cache.ReconcileAsync(receipt);
            await cache.ReconcileAsync(receipt);
            // A receiver may issue a fresh signature/time after a lost response.
            await cache.ReconcileAsync(fixture.Receipt(block));
            var status = await cache.GetStatusAsync();
            Assert.Equal(0, status.PendingBlocks);
            Assert.True(status.StoredPayloadBytes > 0);
            checkpoint = status.Checkpoint;
        }
        await using var reopened = await fixture.OpenAsync(checkpoint);
        Assert.Empty(await reopened.ReadPendingAsync());
        Assert.Equal(2, (await reopened.AppendAsync([TestLedger.Event()])).Content.SequenceNumber);
    }

    [Fact]
    public async Task InvalidReceiptSignatureNeverSettlesEvidence()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var block = await cache.AppendAsync([TestLedger.Event()]);
        var receipt = fixture.Receipt(block);
        receipt.Signature[0] ^= 0xff;
        await Assert.ThrowsAsync<CryptographicException>(() => cache.ReconcileAsync(receipt));
        Assert.Single(await cache.ReadPendingAsync());
    }

    [Theory]
    [InlineData("node")]
    [InlineData("ledger")]
    [InlineData("block")]
    [InlineData("sequence")]
    [InlineData("hash")]
    public async Task ValidSignatureOnWrongReceiptIdentityIsRejected(string changed)
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var block = await cache.AppendAsync([TestLedger.Event()]);
        var content = fixture.Receipt(block).Content;
        content = changed switch
        {
            "node" => content with { NodeId = "other-node" },
            "ledger" => content with { LedgerId = Guid.NewGuid() },
            "block" => content with { BlockId = Guid.NewGuid() },
            "sequence" => content with { SequenceNumber = 2 },
            _ => content with { BlockHash = new string('A', 64) }
        };
        await Assert.ThrowsAsync<InvalidDataException>(() => cache.ReconcileAsync(fixture.Sign(content)));
        Assert.Single(await cache.ReadPendingAsync());
    }

    [Fact]
    public async Task OutOfOrderReceiptsLeaveUnsettledGapsPending()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var first = await cache.AppendAsync([TestLedger.Event()]);
        var second = await cache.AppendAsync([TestLedger.Event()]);
        await cache.ReconcileAsync(fixture.Receipt(second));
        Assert.Equal(first.BlockHash, Assert.Single(await cache.ReadPendingAsync()).BlockHash);
        await cache.VerifyIntegrityAsync();
    }

    [Fact]
    public async Task FailedSigningDoesNotAdvanceTheDurableSequence()
    {
        using var fixture = new TestLedger();
        var signer = new FailingSigner(fixture.Node);
        await using var cache = await DurableTelemetryCache.OpenAsync(fixture.Options, signer, fixture.Node, fixture.Server);
        var first = await cache.AppendAsync([TestLedger.Event()]);
        signer.ShouldFail = true;
        await Assert.ThrowsAsync<IOException>(() => cache.AppendAsync([TestLedger.Event()]));
        signer.ShouldFail = false;
        var second = await cache.AppendAsync([TestLedger.Event()]);
        Assert.Equal(2, second.Content.SequenceNumber);
        Assert.Equal(first.BlockHash, second.Content.PreviousBlockHash);
    }

    [Fact]
    public async Task ConcurrentAppendsHaveOneContinuousSequence()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var blocks = await Task.WhenAll(Enumerable.Range(0, 30).Select(_ => Task.Run(() => cache.AppendAsync([TestLedger.Event()]))));
        Assert.Equal(Enumerable.Range(1, 30).Select(x => (long)x), blocks.Select(b => b.Content.SequenceNumber).Order());
        await cache.VerifyIntegrityAsync();
    }

    [Fact]
    public async Task SecondWriterCannotOpenTheSameLedger()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        await Assert.ThrowsAsync<IOException>(() => fixture.OpenAsync());
    }

    [Fact]
    public async Task CancelledAppendLeavesNoPartialBlock()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cache.AppendAsync([TestLedger.Event()], cancellation.Token));
        Assert.Equal(1, (await cache.AppendAsync([TestLedger.Event()])).Content.SequenceNumber);
    }

    [Fact]
    public async Task PayloadLimitFailsExplicitlyAndPreservesExistingEvidence()
    {
        using var fixture = new TestLedger();
        var item = TestLedger.Event();
        int size = LedgerProtocol.SerializeEvents([item]).Length;
        var options = fixture.Options with { MaximumPayloadBytes = size, MaximumStoredPayloadBytes = size };
        await using var cache = await DurableTelemetryCache.OpenAsync(options, fixture.Node, fixture.Node, fixture.Server);
        await cache.AppendAsync([item]);
        await Assert.ThrowsAsync<IOException>(() => cache.AppendAsync([item]));
        Assert.Single(await cache.ReadPendingAsync());
    }

    [Fact]
    public async Task StartupRejectsPayloadTamperingEvenIfAttackerRecomputesHash()
    {
        using var fixture = new TestLedger();
        SignedTelemetryBlock block;
        await using (var cache = await fixture.OpenAsync()) block = await cache.AppendAsync([TestLedger.Event()]);
        var content = block.Content with { Payload = LedgerProtocol.SerializeEvents([TestLedger.Event(pid: 999)]) };
        var forged = block with { Content = content, BlockHash = Convert.ToHexString(SHA256.HashData(LedgerProtocol.EncodeBlock(content))) };
        fixture.Execute("UPDATE blocks SET body=$body,payload_bytes=$size WHERE sequence=1",
            ("$body", JsonSerializer.SerializeToUtf8Bytes(forged)), ("$size", content.Payload.Length));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.OpenAsync());
    }

    [Theory]
    [InlineData("DELETE FROM blocks WHERE sequence=1")]
    [InlineData("UPDATE ledger SET last_sequence=99")]
    [InlineData("UPDATE blocks SET payload_bytes=1 WHERE sequence=1")]
    [InlineData("UPDATE blocks SET body=x'00' WHERE sequence=1")]
    public async Task StartupRejectsMissingOrAlteredLedgerRecords(string sql)
    {
        using var fixture = new TestLedger();
        await using (var cache = await fixture.OpenAsync())
        {
            await cache.AppendAsync([TestLedger.Event()]);
            await cache.AppendAsync([TestLedger.Event()]);
        }
        fixture.Execute(sql);
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.OpenAsync());
    }

    [Fact]
    public async Task TrustedExternalCheckpointDetectsSuffixRollback()
    {
        using var fixture = new TestLedger();
        SignedTelemetryBlock first;
        LedgerCheckpoint checkpoint;
        await using (var cache = await fixture.OpenAsync())
        {
            first = await cache.AppendAsync([TestLedger.Event()]);
            await cache.AppendAsync([TestLedger.Event()]);
            checkpoint = (await cache.GetStatusAsync()).Checkpoint;
        }
        fixture.Execute("DELETE FROM blocks WHERE sequence=2; UPDATE ledger SET last_sequence=1,tail_hash=$hash", ("$hash", first.BlockHash));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.OpenAsync(checkpoint));
    }

    [Fact]
    public async Task StoredReceiptTamperingIsDetectedOnRestart()
    {
        using var fixture = new TestLedger();
        await using (var cache = await fixture.OpenAsync())
        {
            var block = await cache.AppendAsync([TestLedger.Event()]);
            await cache.ReconcileAsync(fixture.Receipt(block));
        }
        fixture.Execute("UPDATE blocks SET receipt=x'7B7D' WHERE sequence=1");
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.OpenAsync());
    }

    [Fact]
    public async Task InProcessRollbackIsRejectedBeforeAnotherAppend()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        await cache.AppendAsync([TestLedger.Event()]);
        fixture.Execute("DELETE FROM blocks; UPDATE ledger SET last_sequence=0,tail_hash=$hash", ("$hash", LedgerProtocol.GenesisHash));
        await Assert.ThrowsAsync<InvalidDataException>(() => cache.AppendAsync([TestLedger.Event()]));
    }

    [Fact]
    public async Task LedgerCannotBeReopenedUnderAnotherNodeIdentity()
    {
        using var fixture = new TestLedger();
        await using (var cache = await fixture.OpenAsync()) await cache.AppendAsync([TestLedger.Event()]);
        await Assert.ThrowsAsync<InvalidDataException>(() => DurableTelemetryCache.OpenAsync(
            fixture.Options with { NodeId = "different-node" }, fixture.Node, fixture.Node, fixture.Server));
    }
}
