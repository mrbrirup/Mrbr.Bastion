using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Ingestion;

namespace Mrbr.Bastion.Auditing;

public static class AuditAuthentication
{
    public static SignedAuditRequest Verify(SignedAuditRequest request, INodeTrustStore trust)
    {
        if (request?.Content is null || request.Signature is not { Length: > 0 and <= 65536 }) Reject();
        request = request with { Signature = request.Signature.ToArray() };
        var verifier = trust.Resolve(request.Content.NodeId, request.Content.LedgerId);
        if (verifier is null || !AuditProtocol.Verify(request, verifier)) Reject();
        return request;
    }
    public static SignedAuditResponse Verify(SignedAuditResponse response, INodeTrustStore trust)
    {
        if (response?.Content is null || response.Content.Nonce is not { Length: 32 } || response.Signature is not { Length: > 0 and <= 65536 }) Reject();
        response = response with { Content = response.Content with { Nonce = response.Content.Nonce.ToArray() }, Signature = response.Signature.ToArray() };
        var verifier = trust.Resolve(response.Content.NodeId, response.Content.LedgerId);
        if (verifier is null || !AuditProtocol.Verify(response, verifier)) Reject();
        return response;
    }
    public static SignedHealthQuery Verify(SignedHealthQuery query, INodeTrustStore trust)
    {
        if (query?.Content is null || query.Signature is not { Length: > 0 and <= 65536 }) Reject();
        query = query with { Signature = query.Signature.ToArray() };
        var verifier = trust.Resolve(query.Content.NodeId, query.Content.LedgerId);
        if (verifier is null || !AuditProtocol.Verify(query, verifier)) Reject();
        return query;
    }
    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Reject() => throw new AuditRejectedException(AuditFailure.UntrustedIdentity, "The audit signature is not trusted for this enrolled node and ledger.");
}
