using System.Security.Cryptography;
using Mrbr.Bastion.Cryptography;
using Mrbr.Bastion.Ingestion;

namespace Mrbr.Bastion.Server;

public sealed class ServerSettings
{
    public string DatabasePath { get; set; } = "";
    public string ReceiptSigningPrivateKeyPath { get; set; } = "";
    public string? ReceiptSigningKeyId { get; set; }
    public string[] ReceiptVerificationPublicKeyPaths { get; set; } = [];
    public PublicKeySettings[] ReceiptVerificationKeys { get; set; } = [];
    public NodeSettings[] Nodes { get; set; } = [];
    public bool AllowInsecureLoopback { get; set; }
    public long MaximumStoredPayloadBytes { get; set; } = 4L * 1024 * 1024 * 1024;
    public int MaximumConcurrentRequests { get; set; } = 32;
    public string? AuditDatabasePath { get; set; }
    public int MaximumStoredAudits { get; set; } = 100000;
    public long MaximumStoredAuditBytes { get; set; } = 1024L * 1024 * 1024;
    public int MaximumConcurrentAuditRequests { get; set; } = 16;
    public int AuditChallengeLifetimeSeconds { get; set; } = 60;
    public int HeartbeatStaleAfterSeconds { get; set; } = 90;
    public int HeartbeatOfflineAfterSeconds { get; set; } = 300;
    public DashboardSettings Dashboard { get; set; } = new();
    public NotificationSettings Notifications { get; set; } = new();
    public Mrbr.Bastion.Software.Hosting.SoftwareSettings Software { get; set; } = new();
}
public sealed class DashboardSettings
{
    public bool Enabled { get; set; }
    public string? AccessToken { get; set; }
    public Mrbr.Bastion.Operators.AspNetCore.OperatorAuthenticationMode AuthenticationMode{get;set;}
    public string? OperatorDatabasePath{get;set;}
    public int SessionMinutes{get;set;}=480;
    public int MaximumUsers{get;set;}=10000;
    public int MaximumSecurityEvents{get;set;}=1000000;
    public int MaximumOperatorSessions{get;set;}=50000;
    public string? DatabasePath { get; set; }
    public int MaximumStoredAlerts { get; set; } = 100000;
    public int AlertEvaluationIntervalSeconds { get; set; } = 15;
}
public sealed class NodeSettings
{
    public string NodeId { get; set; } = "";
    public string? DisplayName { get; set; }
    public Guid LedgerId { get; set; }
    public PublicKeySettings[] PublicKeys { get; set; } = [];
}
public sealed class PublicKeySettings
{
    public string Path { get; set; } = "";
    public string? KeyId { get; set; }
}

/// <summary>Owns configured providers. Keys are loaded once at startup, without trust-on-first-use.</summary>
public sealed class ServerKeyMaterial : IDisposable
{
    private readonly List<EcdsaSignatureProvider> _providers = [];
    public EcdsaSignatureProvider Signer { get; private set; } = null!;
    public SignatureVerifierSet ReceiptVerifier { get; private set; } = null!;
    public StaticNodeTrustStore NodeTrust { get; private set; } = null!;
    public static ServerKeyMaterial Load(ServerSettings settings, string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(settings.DatabasePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(settings.ReceiptSigningPrivateKeyPath);
        var result = new ServerKeyMaterial();
        try
        {
            result.Signer = result.LoadKey(Path.GetFullPath(settings.ReceiptSigningPrivateKeyPath, root), settings.ReceiptSigningKeyId, publicOnly: false);
            // Fail startup if the configured signer is public-only or otherwise unusable.
            byte[] probe = RandomNumberGenerator.GetBytes(32);
            if (!result.Signer.Verify(result.Signer.Algorithm, result.Signer.KeyId, probe, result.Signer.Sign(probe)))
                throw new CryptographicException("The receipt signing key failed its startup check.");
            var receiptKeys = new List<TrustedSignatureKey> { new(result.Signer.Algorithm, result.Signer.KeyId, result.Signer) };
            foreach (string path in settings.ReceiptVerificationPublicKeyPaths)
            {
                var provider = result.LoadKey(Path.GetFullPath(path, root), null, publicOnly: true);
                receiptKeys.Add(new(provider.Algorithm, provider.KeyId, provider));
            }
            foreach (var item in settings.ReceiptVerificationKeys)
            {
                var provider = result.LoadKey(Path.GetFullPath(item.Path, root), item.KeyId, publicOnly: true);
                receiptKeys.Add(new(provider.Algorithm, provider.KeyId, provider));
            }
            result.ReceiptVerifier = new(receiptKeys);
            result.NodeTrust = new(settings.Nodes.Select(node => new NodeEnrollment(node.NodeId, node.LedgerId,
                new SignatureVerifierSet(node.PublicKeys.Select(item =>
                {
                    var provider = result.LoadKey(Path.GetFullPath(item.Path, root), item.KeyId, publicOnly: true);
                    return new TrustedSignatureKey(provider.Algorithm, provider.KeyId, provider);
                })))));
            return result;
        }
        catch { result.Dispose(); throw; }
    }
    private EcdsaSignatureProvider LoadKey(string path, string? id, bool publicOnly)
    {
        string pem = File.ReadAllText(path);
        if (publicOnly && !pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal))
            throw new InvalidDataException("Verification keys must be SubjectPublicKeyInfo public PEM files.");
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(pem);
            var provider = new EcdsaSignatureProvider(key, id ?? EcdsaSignatureProvider.Fingerprint(key), ownsKey: true);
            _providers.Add(provider);
            return provider;
        }
        catch { key.Dispose(); throw; }
    }
    public void Dispose() { foreach (var provider in _providers) provider.Dispose(); }
}
