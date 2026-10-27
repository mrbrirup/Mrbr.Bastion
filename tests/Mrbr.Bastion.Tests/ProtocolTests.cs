using System.Security.Cryptography;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Cache;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class ProtocolTests
{
    [Theory]
    [InlineData("previous")]
    [InlineData("sequence")]
    [InlineData("node")]
    [InlineData("ledger")]
    [InlineData("time")]
    [InlineData("payload")]
    [InlineData("key")]
    [InlineData("algorithm")]
    [InlineData("count")]
    public async Task SignatureBindsPayloadAndAllSecurityRelevantMetadata(string changed)
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var block = await cache.AppendAsync([TestLedger.Event()]);
        var content = block.Content;
        content = changed switch
        {
            "previous" => content with { PreviousBlockHash = new string('A', 64) },
            "sequence" => content with { SequenceNumber = 2 },
            "node" => content with { NodeId = "other" },
            "ledger" => content with { LedgerId = Guid.NewGuid() },
            "time" => content with { CreatedUtc = content.CreatedUtc.AddSeconds(1) },
            "payload" => content with { Payload = [1, 2, 3] },
            "key" => content with { KeyId = "unknown" },
            "algorithm" => content with { Algorithm = "none" },
            _ => content with { EventCount = 2 }
        };
        var forged = block with { Content = content, BlockHash = Convert.ToHexString(SHA256.HashData(LedgerProtocol.EncodeBlock(content))) };
        Assert.False(LedgerProtocol.VerifyBlock(forged, fixture.Node));
    }

    [Fact]
    public void PublicOnlyProviderVerifiesButCannotSign()
    {
        using var privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(privateKey.ExportSubjectPublicKeyInfo(), out _);
        using var signer = new EcdsaSignatureProvider(privateKey, "key");
        using var verifier = new EcdsaSignatureProvider(publicKey, "key");
        byte[] data = [1, 2, 3];
        var signature = signer.Sign(data);
        Assert.True(verifier.Verify(signer.Algorithm, signer.KeyId, data, signature));
        Assert.False(verifier.Verify("none", signer.KeyId, data, signature));
        Assert.False(verifier.Verify(signer.Algorithm, "unknown", data, signature));
        Assert.False(verifier.Verify(signer.Algorithm, signer.KeyId, [4, 5, 6], signature));
        Assert.ThrowsAny<CryptographicException>(() => verifier.Sign(data));
    }

    [Fact]
    public async Task InvalidUnicodeMetadataCannotCollapseToTheSameCanonicalBytes()
    {
        using var fixture = new TestLedger();
        await using var cache = await fixture.OpenAsync();
        var block = await cache.AppendAsync([TestLedger.Event()]);
        Assert.Throws<InvalidDataException>(() => LedgerProtocol.EncodeBlock(block.Content with { NodeId = "\ud800" }));
        Assert.Throws<InvalidDataException>(() => LedgerProtocol.EncodeBlock(block.Content with { NodeId = "\ud801" }));
    }

    [Fact]
    public void MalformedRecordsFailClosed()
    {
        using var fixture = new TestLedger();
        Assert.False(LedgerProtocol.VerifyBlock(new SignedTelemetryBlock(null!, "", [1]), fixture.Node));
        Assert.False(LedgerProtocol.VerifyReceipt(new SettlementReceipt(null!, [1]), fixture.Server));
    }
}
