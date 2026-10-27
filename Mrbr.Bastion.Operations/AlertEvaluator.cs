using Mrbr.Bastion.Alerting;
using Mrbr.Bastion.Auditing.Contracts;

namespace Mrbr.Bastion.Operations;

public sealed record AlertEvaluationStatus(DateTimeOffset? LastStartedUtc, DateTimeOffset? LastCompletedUtc, int FailedServers, string? Error);
/// <summary>Periodic evaluation is independent of dashboard requests, and failures never resolve existing conditions.</summary>
public sealed class AlertEvaluator(ServerInventory inventory, INodeHealthReader reader, IAlertStore store, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private AlertEvaluationStatus _status = new(null, null, 0, null);
    public AlertEvaluationStatus Status => Volatile.Read(ref _status);
    public async Task EvaluateAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _status = _status with { LastStartedUtc = _time.GetUtcNow(), Error = null };
            int failed = 0;
            foreach (var server in inventory.Servers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                AlertCondition[] conditions; bool verified;
                try
                {
                    var snapshot = await reader.ReadNodeHealthAsync(server.NodeId, server.LedgerId, cancellationToken).ConfigureAwait(false);
                    conditions = HealthAlertPolicy.FromHealth(snapshot.Assessment); verified = true;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception) { failed++; conditions = []; verified = false; }
                await store.ApplyAsync(new(server.NodeId, server.LedgerId, _time.GetUtcNow(), conditions, verified), cancellationToken).ConfigureAwait(false);
            }
            _status = new(_status.LastStartedUtc, _time.GetUtcNow(), failed, failed == 0 ? null : "Some server health evidence could not be verified.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            _status = _status with { Error = "Alert evaluation or persistence is unavailable." }; throw;
        }
        finally { _gate.Release(); }
    }
}
