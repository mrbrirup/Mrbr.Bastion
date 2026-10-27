using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Mrbr.Bastion.Cryptography;

namespace Mrbr.Bastion.Configuration;

public static class PemKeyService
{
    public static string CreatePair(LauncherProfile profile, PemKeyPair pair)
    {
        string privatePath = profile.Resolve(pair.PrivateKeyPath), publicPath = profile.Resolve(pair.PublicKeyPath);
        if (string.Equals(privatePath, publicPath, StringComparison.OrdinalIgnoreCase)
            || File.Exists(privatePath) || File.Exists(publicPath))
            throw new IOException("Choose two different, unused key paths. Existing keys are never overwritten.");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Directory.CreateDirectory(Path.GetDirectoryName(privatePath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(publicPath)!);
        bool privateCreated = false, publicCreated = false;
        try
        {
            using (var stream = CreatePrivateFile(privatePath))
            {
                privateCreated = true;
                using var writer = new StreamWriter(stream, leaveOpen: true);
                writer.Write(key.ExportPkcs8PrivateKeyPem()); writer.Flush(); stream.Flush(true);
            }
            using (var stream = new FileStream(publicPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream)) { publicCreated = true; writer.Write(key.ExportSubjectPublicKeyInfoPem()); writer.Flush(); stream.Flush(true); }
            return EcdsaSignatureProvider.Fingerprint(key);
        }
        catch { if (privateCreated) File.Delete(privatePath); if (publicCreated) File.Delete(publicPath); throw; }
    }
    private static FileStream CreatePrivateFile(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));
            return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, security);
        }
        return new FileStream(path, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write,
            Share = FileShare.None, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite });
    }
    public static string VerifyPair(LauncherProfile profile, PemKeyPair pair)
    {
        using var privateKey = ECDsa.Create(); privateKey.ImportFromPem(File.ReadAllText(profile.Resolve(pair.PrivateKeyPath)));
        using var publicKey = ECDsa.Create(); publicKey.ImportFromPem(File.ReadAllText(profile.Resolve(pair.PublicKeyPath)));
        if (privateKey.KeySize != 256 || privateKey.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value
            || !privateKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(publicKey.ExportSubjectPublicKeyInfo()))
            throw new CryptographicException("The configured keys are not a matching P-256 pair.");
        byte[] probe = RandomNumberGenerator.GetBytes(32);
        if (!publicKey.VerifyData(probe, privateKey.SignData(probe, HashAlgorithmName.SHA256), HashAlgorithmName.SHA256))
            throw new CryptographicException("The private key failed a signing check.");
        return EcdsaSignatureProvider.Fingerprint(publicKey);
    }
    public static void ApplyPaths(LauncherProfile profile)
    {
        profile.Receiver.Bastion.ReceiptSigningPrivateKeyPath = profile.Keys.Receiver.PrivateKeyPath;
        profile.Collector.NodePrivateKeyPath = profile.Inventory.NodePrivateKeyPath = profile.Keys.Node.PrivateKeyPath;
        profile.Collector.ReceiverPublicKeyPath = profile.Inventory.ReceiverPublicKeyPath = profile.Keys.Receiver.PublicKeyPath;
    }
}
