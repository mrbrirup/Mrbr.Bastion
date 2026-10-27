namespace Mrbr.Bastion.Auditing.Contracts;

public sealed record AuditHistoryPage(AuditRecord[] Records, long? NextBeforeSequence);

/// <summary>Trusted operator read interface. Only committed, signature-verified audits are returned.</summary>
public interface IAuditHistoryReader
{
    Task<AuditHistoryPage> ReadHistoryAsync(string nodeId, Guid ledgerId, long? beforeSequence = null,
        int limit = 25, CancellationToken cancellationToken = default);
}
