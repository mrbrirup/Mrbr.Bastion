using System.Globalization;
using Mrbr.Bastion.Core;
using Mrbr.Bastion.Cache;
using System.Text.Json;

namespace Mrbr.Bastion.Console;

public sealed class CollectorCommandLine
{
    public string[] Positional { get; private set; } = [];
    public bool Inspect { get; private set; }
    public bool SendOnly { get; private set; }
    public bool ReadHealth { get; private set; }
    public bool NoAudits { get; private set; }
    public bool ExcludeManagedFileIo { get; private set; } = true;
    public int[] AdditionalFileIoProcessIds { get; private set; } = [];
    public TelemetryMonitorOptions Monitor { get; private set; } = new();
    public int EtwBufferMegabytes { get; private set; } = 64;
    public long MaximumStoredPayloadBytes { get; private set; } = 512L * 1024 * 1024;
    public string? RetentionConfigurationPath { get; private set; }
    public bool Retain { get; private set; }
    public bool Compact { get; private set; }

    public CacheRetentionOptions LoadRetention()
    {
        if (RetentionConfigurationPath is null) return new();
        if (new FileInfo(RetentionConfigurationPath).Length > 65536) throw new InvalidDataException("Retention configuration exceeds 64 KiB.");
        var policy = JsonSerializer.Deserialize<CacheRetentionOptions>(File.ReadAllText(RetentionConfigurationPath),
            new JsonSerializerOptions(JsonSerializerDefaults.Web) { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow })
            ?? throw new InvalidDataException("Missing retention configuration.");
        policy.Validate(); return policy;
    }

    public static CollectorCommandLine Parse(string[] arguments)
    {
        var result = new CollectorCommandLine(); var positional = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal); var processIds = new HashSet<int>();
        int queue = 8192, batch = 100, flush = 1000;
        for (int i = 0; i < arguments.Length; i++)
        {
            string argument = arguments[i];
            if (!argument.StartsWith("--", StringComparison.Ordinal)) { positional.Add(argument); continue; }
            if (argument != "--exclude-file-process" && !seen.Add(argument)) throw new ArgumentException("Duplicate collector option: " + argument);
            int Number()
            {
                if (++i == arguments.Length || !int.TryParse(arguments[i], NumberStyles.None, CultureInfo.InvariantCulture, out int value))
                    throw new ArgumentException("Expected a positive integer after " + argument);
                return value;
            }
            switch (argument)
            {
                case "--inspect": result.Inspect = true; break;
                case "--send-only": result.SendOnly = true; break;
                case "--health": result.ReadHealth = true; break;
                case "--retain": result.Retain = true; break;
                case "--compact": result.Compact = true; break;
                case "--cache-capacity-mb": result.MaximumStoredPayloadBytes = checked(Number() * 1024L * 1024); break;
                case "--cache-capacity-bytes":
                    if (++i == arguments.Length || !long.TryParse(arguments[i], NumberStyles.None, CultureInfo.InvariantCulture, out long capacity))
                        throw new ArgumentException("Expected a cache capacity in bytes.");
                    result.MaximumStoredPayloadBytes = capacity; break;
                case "--retention-config":
                    if (++i == arguments.Length || string.IsNullOrWhiteSpace(arguments[i])) throw new ArgumentException("Expected a retention configuration path.");
                    result.RetentionConfigurationPath = arguments[i]; break;
                case "--no-audits": result.NoAudits = true; break;
                case "--include-managed-file-io": result.ExcludeManagedFileIo = false; break;
                case "--queue-capacity": queue = Number(); break;
                case "--batch-size": batch = Number(); break;
                case "--flush-ms": flush = Number(); break;
                case "--etw-buffer-mb": result.EtwBufferMegabytes = Number(); break;
                case "--exclude-file-process":
                    int id = Number();
                    if (id <= 0 || !processIds.Add(id) || processIds.Count > 60) throw new ArgumentException("Specify at most 60 distinct positive file-I/O process IDs.");
                    break;
                default: throw new ArgumentException("Unknown collector option: " + argument);
            }
        }
        result.Monitor = new() { QueueCapacity = queue, BatchSize = batch, FlushInterval = TimeSpan.FromMilliseconds(flush) };
        result.Monitor.Validate();
        if (batch > 1000) throw new ArgumentException("The collector's durable cache supports batches of at most 1,000 events.");
        if (result.EtwBufferMegabytes is < 1 or > 1024) throw new ArgumentException("ETW buffer size must be between 1 and 1024 MB.");
        if (result.MaximumStoredPayloadBytes < 4L * 1024 * 1024) throw new ArgumentException("Cache capacity must be at least 4 MB.");
        if (seen.Contains("--cache-capacity-mb") && seen.Contains("--cache-capacity-bytes")) throw new ArgumentException("Choose one cache capacity unit.");
        result.Positional = positional.ToArray(); result.AdditionalFileIoProcessIds = processIds.ToArray();
        if (result.Positional.Length is not (4 or 6) || (result.SendOnly || result.ReadHealth) && result.Positional.Length != 6
            || new[] { result.Inspect, result.SendOnly, result.ReadHealth, result.Retain, result.Compact }.Count(x => x) > 1
            || result.Positional.Length == 6 && result.Positional[4] is not ("http" or "grpc")) throw new ArgumentException("Invalid collector arguments. Use --help for usage.");
        return result;
    }
}
