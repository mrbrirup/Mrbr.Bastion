using System.Security.Cryptography;
using System.Text.Json;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Archiving;
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Inventory.Contracts;

namespace Mrbr.Bastion.Cache.Tool;

public sealed class MaintenanceSettings
{
    public string NodeId { get; set; } = "";
    public string DatabasePath { get; set; } = "";
    public string NodePrivateKeyPath { get; set; } = "";
    public string ReceiverPublicKeyPath { get; set; } = "";
    public bool InventoryPayloads { get; set; }
    public long MaximumStoredPayloadBytes { get; set; } = 512L * 1024 * 1024;
    public CacheRetentionOptions Retention { get; set; } = new();
}
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length is 4 or 5 && args[0] == "verify-archive" && (args.Length == 4 || args[4] == "--inventory"))
            {
                string file=args[1],publicPath=args[2],receiverPath=args[3];
                using var key = ECDsa.Create(); key.ImportFromPem(await File.ReadAllTextAsync(publicPath));
                using var receiverKey = ECDsa.Create(); receiverKey.ImportFromPem(await File.ReadAllTextAsync(receiverPath));
                using var node = new Cryptography.EcdsaSignatureProvider(key, Cryptography.EcdsaSignatureProvider.Fingerprint(key));
                using var receiver = new Cryptography.EcdsaSignatureProvider(receiverKey, Cryptography.EcdsaSignatureProvider.Fingerprint(receiverKey));
                var segment = ArchiveFile.Verify(file,node,receiver,args.Length==5?[new InventoryPayloadCodec()]:[]);
                Console.WriteLine(JsonSerializer.Serialize(segment,ArchiveProtocol.Json)); return 0;
            }
            if (args is not [var operation, var config] || operation is not ("verify" or "retain" or "compact" or "status"))
            {
                Console.WriteLine("Usage: Mrbr.Bastion.Cache.Tool verify|status|retain|compact <cache-maintenance.json>\n       Mrbr.Bastion.Cache.Tool verify-archive <file.bastion-archive> <node-public.pem> <receiver-public.pem> [--inventory]\nMaintenance requires stopped agent hosts. Verify/status do not apply retention. Retain performs one bounded configured pass; no archives or unsettled blocks are expired. Compact verifies then VACUUMs the resident database. Archive verification needs only public keys.");
                return args.Length == 0 || args is ["--help"] ? 0 : 1;
            }
            if (new FileInfo(config).Length > 65536) throw new InvalidDataException("Maintenance configuration exceeds 64 KiB.");
            var settings = ArchiveProtocol.Decode<MaintenanceSettings>(await File.ReadAllBytesAsync(config));
            string root = Path.GetDirectoryName(Path.GetFullPath(config))!;
            string Resolve(string p) => Path.GetFullPath(p,root);
            string database = Resolve(settings.DatabasePath);
            if (!File.Exists(database)) throw new FileNotFoundException("Maintenance requires an existing outbox.",database);
            using var signingKey=ECDsa.Create(); signingKey.ImportFromPem(await File.ReadAllTextAsync(Resolve(settings.NodePrivateKeyPath)));
            using var serverKey=ECDsa.Create(); serverKey.ImportFromPem(await File.ReadAllTextAsync(Resolve(settings.ReceiverPublicKeyPath)));
            using var signer=new Cryptography.EcdsaSignatureProvider(signingKey,Cryptography.EcdsaSignatureProvider.Fingerprint(signingKey));
            using var server=new Cryptography.EcdsaSignatureProvider(serverKey,Cryptography.EcdsaSignatureProvider.Fingerprint(serverKey));
            await using var cache=await DurableTelemetryCache.OpenAsync(new(){NodeId=settings.NodeId,DatabasePath=database,MaximumStoredPayloadBytes=settings.MaximumStoredPayloadBytes,
                Retention=settings.Retention,AdditionalPayloadCodecs=settings.InventoryPayloads?[new InventoryPayloadCodec()]:[]},signer,signer,server);
            if (operation=="retain")
            {
                if(!settings.Retention.Enabled)throw new ArgumentException("Enable the retention policy explicitly before running retain.");
                Console.WriteLine(JsonSerializer.Serialize(await cache.ApplyRetentionAsync(),ArchiveProtocol.Json));
            }
            if(operation=="compact")await cache.CompactAsync();
            var storage=await cache.GetStorageStatusAsync();var segments=await cache.GetArchivesAsync();
            var referenced=segments.Select(s=>s.FileName).ToHashSet(StringComparer.OrdinalIgnoreCase);
            string[] orphans=Directory.Exists(storage.ArchiveDirectory)?Directory.EnumerateFiles(storage.ArchiveDirectory,"*.bastion-archive").Select(Path.GetFileName).Where(n=>!referenced.Contains(n!)).Select(n=>n!).ToArray():[];
            long? firstPending=(await cache.ReadPendingAsync(1)).FirstOrDefault()?.Content.SequenceNumber;
            Console.WriteLine(JsonSerializer.Serialize(new{Status=await cache.GetStatusAsync(),Storage=storage,FirstPendingSequence=firstPending,Archives=segments,UnreferencedFiles=orphans},ArchiveProtocol.Json));return 0;
        }
        catch(Exception error)when(error is IOException or InvalidDataException or ArgumentException or CryptographicException or UnauthorizedAccessException)
        {Console.Error.WriteLine(error.Message);return 1;}
    }
}
