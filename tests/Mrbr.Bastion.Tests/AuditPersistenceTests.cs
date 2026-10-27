using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Cryptography;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class AuditPersistenceTests
{
    [Fact]
    public async Task PendingChallengeAndNonceSurviveRestart()
    {
        await using var f = await AuditFixture.CreateAsync();
        var request = f.Request(); var c = await f.Service.CreateChallengeAsync(request); var response = await f.ResponseAsync(c);
        await f.ReopenAsync();
        Assert.Equal(c.Signature, (await f.Service.CreateChallengeAsync(request)).Signature);
        Assert.Equal(1, (await f.Service.SubmitAsync(response)).Content.AuditSequenceNumber);
    }
    [Theory]
    [InlineData("UPDATE audit_entries SET challenge_json=x'7B7D'")]
    [InlineData("UPDATE audit_entries SET response_json=x'7B7D'")]
    [InlineData("UPDATE audit_entries SET result_json=x'7B7D'")]
    [InlineData("UPDATE audit_entries SET expires_ticks=expires_ticks+1")]
    [InlineData("UPDATE audit_entries SET accepted_ticks=accepted_ticks+1")]
    [InlineData("UPDATE node_heads SET sequence=99")]
    public async Task RestartRejectsModifiedSignedEvidenceOrState(string sql)
    {
        await using var f = await AuditFixture.CreateAsync(); await f.AuditAsync(); await f.Store.DisposeAsync();
        Execute(f, sql);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.ReopenAsync());
    }
    [Fact]
    public async Task DeletedAssessmentBreaksRetainedHistory()
    {
        await using var f = await AuditFixture.CreateAsync(); await f.AuditAsync(); await f.AuditAsync(); await f.Store.DisposeAsync();
        Execute(f, "DELETE FROM audit_entries WHERE accepted_sequence=1");
        await Assert.ThrowsAsync<InvalidDataException>(() => f.ReopenAsync());
    }
    [Fact]
    public async Task RuntimeHeadModificationCannotReturnFakeHealthyState()
    {
        await using var f = await AuditFixture.CreateAsync(); await f.AuditAsync();
        Execute(f, "UPDATE node_heads SET sequence=99");
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Service.GetHealthAsync(f.Query()));
    }
    [Fact]
    public async Task ReceiverEvidenceMissingBehindASignedAnchorCannotYieldFreshHealthyReports()
    {
        await using var f = await AuditFixture.CreateAsync(); await f.AuditAsync();
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.Ledger.Options.DatabasePath, Pooling = false }.ToString()))
        {
            connection.Open(); using var command = connection.CreateCommand(); command.CommandText = "DELETE FROM ingested_blocks"; command.ExecuteNonQuery();
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Service.GetHealthAsync(f.Query()));
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Service.CreateChallengeAsync(f.Request()));
    }

    [Fact]
    public async Task CapacityLimitsPreserveExistingProofAndDoNotRefreshHealth()
    {
        await using var f = await AuditFixture.CreateAsync();
        await f.ReopenAsync(f.Options with { MaximumStoredAudits = 1 });
        var (response, original) = await f.AuditAsync(); f.Clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(AuditFailure.CapacityExceeded, (await Assert.ThrowsAsync<AuditRejectedException>(() => f.Service.CreateChallengeAsync(f.Request()))).Failure);
        Assert.Equal(original.Signature, (await f.Service.SubmitAsync(response)).Signature);
        Assert.Equal(original.Content.AcceptedUtc, (await f.Service.GetHealthAsync(f.Query())).Content.LastAcceptedAuditUtc);
    }
    [Fact]
    public async Task ProcessDeathPreservesConsumedNonceAndSignedAssessment()
    {
        await using var f = await AuditFixture.CreateAsync();
        var challenge = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(challenge);
        await f.Store.DisposeAsync();
        string responsePath = Path.Combine(f.Ledger.Local.DirectoryPath, "audit-response.json");
        string nodeKeyPath = Path.Combine(f.Ledger.Local.DirectoryPath, "audit-node-public.pem");
        string receiverKeyPath = Path.Combine(f.Ledger.Local.DirectoryPath, "audit-receiver-private.pem");
        File.WriteAllBytes(responsePath, TelemetryJson.Encode(response));
        File.WriteAllText(nodeKeyPath, f.Ledger.Local.NodeKey.ExportSubjectPublicKeyInfoPem());
        File.WriteAllText(receiverKeyPath, f.Ledger.Local.ServerKey.ExportPkcs8PrivateKeyPem());
        using var child = RecoveryAndEtwTests.StartProbe("--audit", f.Options.DatabasePath, responsePath, nodeKeyPath, receiverKeyPath);
        try { Assert.Equal("READY", await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15))); }
        finally
        {
            if (!child.HasExited) child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        }
        await TestLedger.AfterProcessExitAsync(()=>f.ReopenAsync());
        var original = (await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId))!.Result;
        f.Clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(original.Signature, (await f.Service.SubmitAsync(response)).Signature);
        Assert.Equal(1, original.Content.AuditSequenceNumber);
        Assert.Equal(ServerHealthState.Offline, (await f.Service.GetHealthAsync(f.Query())).Content.Assessment.State);
    }

    [Fact]
    public async Task CancellationAfterSigningRollsBackNonceConsumption()
    {
        await using var f = await AuditFixture.CreateAsync();
        var c = await f.Service.CreateChallengeAsync(f.Request()); var response = await f.ResponseAsync(c);
        using var stop = new CancellationTokenSource();
        var signer = new CancelingSigner(f.Ledger.Local.Server, stop);
        var service = new HeartbeatAuditService(f.Ledger.Trust, f.Ledger.Store, f.Store, signer, f.Ledger.Local.Server, timeProvider: f.Clock);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.SubmitAsync(response, stop.Token));
        Assert.Null(await f.Store.ReadLatestAsync(f.NodeId, f.LedgerId));
        Assert.Equal(1, (await f.Service.SubmitAsync(response)).Content.AuditSequenceNumber);
    }
    [Fact]
    public async Task HistoricalVerificationKeysAllowRotationAndExactOldReceiptRetries()
    {
        await using var f = await AuditFixture.CreateAsync();
        var (response, original) = await f.AuditAsync();
        using var rotated = new EcdsaSignatureProvider(ECDsa.Create(ECCurve.NamedCurves.nistP256), "rotated-receiver", ownsKey: true);
        var old = f.Ledger.Local.Server;
        var ring = new SignatureVerifierSet([new(old.Algorithm, old.KeyId, old), new(rotated.Algorithm, rotated.KeyId, rotated)]);
        await f.ReopenAsync(verifier: ring, signer: rotated);
        Assert.Equal(original.Signature, (await f.Service.SubmitAsync(response)).Signature);
        var next = (await f.AuditAsync()).Result;
        Assert.Equal(rotated.KeyId, next.Content.KeyId); Assert.Equal(2, next.Content.AuditSequenceNumber);
        await f.Store.VerifyIntegrityAsync();
    }
    private static void Execute(AuditFixture f, string sql)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.Options.DatabasePath, Pooling = false }.ToString());
        connection.Open(); using var command = connection.CreateCommand(); command.CommandText = sql; command.ExecuteNonQuery();
    }
    private sealed class CancelingSigner(ISignatureSigner inner, CancellationTokenSource stop) : ISignatureSigner
    {
        public string Algorithm => inner.Algorithm;
        public string KeyId => inner.KeyId;
        public byte[] Sign(ReadOnlySpan<byte> data) { var signature = inner.Sign(data); stop.Cancel(); return signature; }
    }
}
