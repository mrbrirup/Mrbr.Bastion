namespace Mrbr.Bastion.Dashboard;

public sealed record DashboardOptions
{
    public string? AccessToken { get; init; }
    public Mrbr.Bastion.Operators.AspNetCore.OperatorAuthenticationMode AuthenticationMode{get;init;}
    public int SessionMinutes{get;init;}=480;
    public bool AllowInsecureLoopback { get; init; }
    public int AlertEvaluationIntervalSeconds { get; init; } = 15;
    internal void Validate()
    {
        new Mrbr.Bastion.Operators.AspNetCore.OperatorAuthenticationOptions{Mode=AuthenticationMode,LegacyAccessToken=AccessToken,SessionMinutes=SessionMinutes}.Validate();
        if (AlertEvaluationIntervalSeconds is < 1 or > 300) throw new ArgumentOutOfRangeException(nameof(AlertEvaluationIntervalSeconds));
    }
}
