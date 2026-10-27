using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Auditing.Contracts;

namespace Mrbr.Bastion.Operations;

public sealed record MonitoredServer(string NodeId, Guid LedgerId, string DisplayName);
public sealed class ServerInventory
{
    private readonly MonitoredServer[] _servers;
    public ServerInventory(IEnumerable<MonitoredServer> servers)
    {
        _servers = servers.OrderBy(s => s.NodeId, StringComparer.Ordinal).ThenBy(s => s.LedgerId).ToArray();
        if (_servers.Length > 10000 || _servers.Any(s => string.IsNullOrWhiteSpace(s.NodeId) || s.NodeId.Length > 256
            || s.LedgerId == Guid.Empty || string.IsNullOrWhiteSpace(s.DisplayName) || s.DisplayName.Length > 256)
            || _servers.Select(s => (s.NodeId, s.LedgerId)).Distinct().Count() != _servers.Length) throw new ArgumentException("Invalid server inventory.", nameof(servers));
    }
    public IReadOnlyList<MonitoredServer> Servers => Array.AsReadOnly(_servers);
    public bool Contains(string nodeId, Guid ledgerId) => _servers.Any(s => s.NodeId == nodeId && s.LedgerId == ledgerId);
}
public sealed record ServerOverview(MonitoredServer Server, NodeHealthSnapshot? Health, string? Error);
public sealed record FleetSummary(int Total, int Healthy, int Degraded, int Critical, int Offline, int Unknown, int VerificationUnavailable);
public sealed record FleetPage(DateTimeOffset GeneratedUtc, FleetSummary Summary, ServerOverview[] Servers,
    int TotalMatches, int Page, int PageSize, AlertCounts Alerts);

/// <summary>Read-only operator queries. Dashboard reads cannot refresh heartbeat liveness or alter alerts.</summary>
public sealed class OperationsService(ServerInventory inventory, INodeHealthReader health, IAuditHistoryReader history,
    IAlertStore alerts, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    public async Task<FleetPage> ReadFleetAsync(string? search = null, ServerHealthState? state = null,
        int page = 1, int pageSize = 25, CancellationToken cancellationToken = default)
    {
        if (page < 1 || page > 10000 || pageSize is < 1 or > 100 || search?.Length > 256 || (state is { } s && !Enum.IsDefined(s)))
            throw new ArgumentException("Invalid fleet query.");
        var all = new List<ServerOverview>();
        foreach (var server in inventory.Servers) all.Add(await ReadServerAsync(server.NodeId, server.LedgerId, cancellationToken).ConfigureAwait(false));
        int Count(ServerHealthState s) => all.Count(x => x.Health?.Assessment.State == s);
        var summary = new FleetSummary(all.Count, Count(ServerHealthState.Healthy), Count(ServerHealthState.Degraded), Count(ServerHealthState.Critical),
            Count(ServerHealthState.Offline), Count(ServerHealthState.Unknown), all.Count(x => x.Error is not null));
        var matches = all.Where(x => (string.IsNullOrWhiteSpace(search) || x.Server.NodeId.Contains(search, StringComparison.OrdinalIgnoreCase)
            || x.Server.DisplayName.Contains(search, StringComparison.OrdinalIgnoreCase) || x.Server.LedgerId.ToString().Contains(search, StringComparison.OrdinalIgnoreCase))
            && (state is null || x.Health?.Assessment.State == state)).ToArray();
        return new(_time.GetUtcNow(), summary, matches.Skip((page - 1) * pageSize).Take(pageSize).ToArray(), matches.Length,
            page, pageSize, await alerts.CountAsync(cancellationToken).ConfigureAwait(false));
    }
    public async Task<ServerOverview> ReadServerAsync(string nodeId, Guid ledgerId, CancellationToken cancellationToken = default)
    {
        RequireEnrollment(nodeId, ledgerId);
        var server = inventory.Servers.Single(s => s.NodeId == nodeId && s.LedgerId == ledgerId);
        try { return new(server, await health.ReadNodeHealthAsync(nodeId, ledgerId, cancellationToken).ConfigureAwait(false), null); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return new(server, null, HealthAlertPolicy.VerificationUnavailable); }
    }
    public Task<AuditHistoryPage> ReadHistoryAsync(string nodeId, Guid ledgerId, long? beforeSequence = null, int limit = 25, CancellationToken cancellationToken = default)
    { RequireEnrollment(nodeId, ledgerId); return history.ReadHistoryAsync(nodeId, ledgerId, beforeSequence, limit, cancellationToken); }
    public void RequireEnrollment(string nodeId, Guid ledgerId)
    { if (!inventory.Contains(nodeId, ledgerId)) throw new KeyNotFoundException("Unknown server enrollment."); }
}
