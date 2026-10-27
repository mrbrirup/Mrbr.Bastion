using System.Collections;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Mrbr.Bastion.Configuration;

/// <summary>Uses actual host DTOs for runtime documents; secret values stay in memory.</summary>
public static class ProfileStorage
{
    public static readonly HashSet<string> SecretNames = new(StringComparer.Ordinal)
        { "Password", "AccessToken", "BearerToken", "SigningKey", "NvdApiKey" };
    public static JsonSerializerOptions Json { get; } = CreateJson();
    private static JsonSerializerOptions CreateJson()
    {
        var resolver = new DefaultJsonTypeInfoResolver();
        resolver.Modifiers.Add(info =>
        {
            foreach (var property in info.Properties)
                if (property.AttributeProvider is PropertyInfo reflection && SecretNames.Contains(reflection.Name))
                    property.ShouldSerialize = (_, _) => false;
        });
        return new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true, MaxDepth = 32, TypeInfoResolver = resolver, RespectNullableAnnotations = true,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            Converters = { new JsonStringEnumConverter(allowIntegerValues: false) }
        };
    }
    public static LauncherProfile Load(string path)
    {
        if (new FileInfo(path).Length > 2 * 1024 * 1024) throw new InvalidDataException("Profile exceeds 2 MiB.");
        var profile = JsonSerializer.Deserialize<LauncherProfile>(File.ReadAllText(path), Json)
            ?? throw new InvalidDataException("Profile is empty.");
        if (profile.Version != 1 || !Path.IsPathFullyQualified(profile.DeploymentDirectory)
            || profile.Runtime is null || profile.Keys?.Receiver is null || profile.Keys.Node is null
            || profile.Receiver?.Bastion is null || profile.Receiver.Kestrel?.Endpoints?.Https?.Certificate is null
            || profile.Collector is null || profile.Inventory is null)
            throw new InvalidDataException("Unsupported or incomplete desktop profile.");
        return profile;
    }
    public static void Save(string path, LauncherProfile profile) => Write(path, JsonSerializer.Serialize(profile, Json));
    public static void Export(LauncherProfile profile)
    {
        string receiver = JsonSerializer.Serialize(profile.Receiver, Json);
        string inventory = JsonSerializer.Serialize(profile.Inventory, Json);
        Write(profile.ReceiverFile, receiver);
        Write(profile.InventoryFile, inventory);
        Write(profile.RetentionFile, JsonSerializer.Serialize(profile.Collector.Retention, Json));
    }
    private static void Write(string path, string contents)
    {
        path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream)) { writer.Write(contents); writer.Flush(); stream.Flush(true); }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public static Dictionary<string, string> ReceiverSecrets(ReceiverDocument receiver)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        void Visit(object? value, string prefix)
        {
            if (value is null || value is string || value is Uri || value.GetType().IsValueType) return;
            if (value is IEnumerable collection)
            {
                int index = 0;
                foreach (var item in collection) Visit(item, prefix + "__" + index++);
                return;
            }
            foreach (var property in value.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(p => p.CanRead))
            {
                string name = prefix.Length == 0 ? property.Name : prefix + "__" + property.Name;
                object? child = property.GetValue(value);
                if (SecretNames.Contains(property.Name)) { if (child is string { Length: > 0 } secret) result[name] = secret; }
                else Visit(child, name);
            }
        }
        Visit(receiver, "");
        return result;
    }
}
