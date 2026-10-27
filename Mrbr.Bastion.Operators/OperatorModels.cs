using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mrbr.Bastion.Operators;

public enum OperatorRole { Viewer, Operator, Analyst, Administrator }
public static class OperatorPermissions
{
    public const string Read="dashboard.read",Evidence="evidence.read",Acknowledge="alerts.acknowledge",Retry="notifications.retry",
        Review="mappings.review",Search="intelligence.search",ManageUsers="users.manage",SecurityHistory="security.history";
    public static readonly string[] All=[Read,Evidence,Acknowledge,Retry,Review,Search,ManageUsers,SecurityHistory];
    public static string[] ForRoles(IEnumerable<OperatorRole> roles)=>roles.SelectMany(role=>role switch
    {
        OperatorRole.Viewer=>new[]{Read},OperatorRole.Operator=>[Read,Evidence,Acknowledge,Retry],
        OperatorRole.Analyst=>[Read,Evidence,Review,Search],OperatorRole.Administrator=>All,_=>Array.Empty<string>()
    }).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
}
public sealed record OperatorAccount(Guid Id,string UserName,string DisplayName,OperatorRole[] Roles,bool Enabled,bool MustChangePassword,
    long Revision,DateTimeOffset CreatedUtc,DateTimeOffset UpdatedUtc,DateTimeOffset? LastLoginUtc=null);
public sealed record OperatorCredential(OperatorAccount Account,[property:JsonIgnore]string PasswordHash,[property:JsonIgnore]Guid SecurityStamp,int FailedAttempts,DateTimeOffset? LockedUntilUtc)
{public override string ToString()=>$"OperatorCredential {{ UserId = {Account.Id:D}, Credentials = [redacted] }}";}
public sealed record OperatorActor(Guid UserId,[property:JsonIgnore]Guid SecurityStamp)
{public override string ToString()=>$"OperatorActor {{ UserId = {UserId:D} }}";}
public sealed record OperatorSession(Guid Id,OperatorAccount Account,[property:JsonIgnore]Guid SecurityStamp,DateTimeOffset CreatedUtc,DateTimeOffset ExpiresUtc)
{public override string ToString()=>$"OperatorSession {{ Id = {Id:D}, UserId = {Account.Id:D}, ExpiresUtc = {ExpiresUtc:O} }}";}
public sealed record OperatorPage(OperatorAccount[] Users,string? NextAfter);
public sealed record OperatorSecurityEvent(long Sequence,DateTimeOffset OccurredUtc,Guid? ActorId,string Actor,string Action,Guid? TargetId,string? Target,string? Detail,string? RemoteAddress);
public sealed record OperatorSecurityPage(OperatorSecurityEvent[] Events,long? NextBefore);
public sealed class OperatorConflictException(string code):Exception(code){public string Code{get;}=code;}
public sealed class OperatorAccessException():Exception("Operator access is no longer valid.");
public interface IOperatorStore:IAsyncDisposable
{
    Task<OperatorCredential?> FindCredentialsAsync(string normalizedName,CancellationToken ct=default);
    Task<OperatorSession?> RecordLoginAsync(string normalizedName,Guid? expectedStamp,bool passwordMatched,string? remote,DateTimeOffset now,TimeSpan lifetime,CancellationToken ct=default);
    Task<OperatorSession?> ReadSessionAsync(Guid sessionId,Guid userId,Guid stamp,DateTimeOffset now,CancellationToken ct=default);
    Task RevokeSessionAsync(Guid sessionId,Guid userId,DateTimeOffset now,CancellationToken ct=default);
    Task<OperatorAccount> CreateAsync(string name,string displayName,OperatorRole[] roles,string passwordHash,bool mustChange,OperatorActor? actor,bool bootstrap,DateTimeOffset now,CancellationToken ct=default);
    Task<OperatorAccount> UpdateAsync(Guid id,long expectedRevision,string displayName,OperatorRole[] roles,bool enabled,OperatorActor actor,DateTimeOffset now,CancellationToken ct=default);
    Task ResetPasswordAsync(Guid id,long expectedRevision,string hash,OperatorActor actor,DateTimeOffset now,CancellationToken ct=default);
    Task<bool> ChangePasswordAsync(OperatorActor actor,string expectedHash,string newHash,DateTimeOffset now,CancellationToken ct=default);
    Task RevokeAllAsync(Guid id,long expectedRevision,OperatorActor actor,DateTimeOffset now,CancellationToken ct=default);
    Task RecoverAdministratorAsync(string name,string passwordHash,DateTimeOffset now,CancellationToken ct=default);
    Task<OperatorCredential?> FindByIdAsync(Guid id,CancellationToken ct=default);
    Task<OperatorPage> ReadUsersAsync(string? after=null,int limit=50,CancellationToken ct=default);
    Task<OperatorSecurityPage> ReadSecurityAsync(long? before=null,int limit=50,CancellationToken ct=default);
}
public static class OperatorValidation
{
    public static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web){PropertyNameCaseInsensitive=false,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=16,Converters={new JsonStringEnumConverter(allowIntegerValues:false)}};
    public static string Name(string name)
    {
        if(string.IsNullOrWhiteSpace(name)||name.Length is <3 or >64||name.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c is not('.' or '-' or '_')))throw new ArgumentException("Usernames require 3 to 64 ASCII letters, digits, dots, underscores or hyphens.");
        return name.ToLowerInvariant();
    }
    public static void Display(string value){if(string.IsNullOrWhiteSpace(value)||value.Length>128||value.Any(char.IsControl))throw new ArgumentException("A display name of up to 128 characters is required.");try{_=new UTF8Encoding(false,true).GetByteCount(value);}catch(EncoderFallbackException){throw new ArgumentException("Invalid display name Unicode.");}}
    public static void Roles(OperatorRole[] roles){if(roles is null||roles.Length is <1 or >4||roles.Any(r=>!Enum.IsDefined(r))||roles.Distinct().Count()!=roles.Length)throw new ArgumentException("Choose one or more distinct supported roles.");}
    public static void Password(string value){if(value is null||value.Length is <15 or >128||value.Any(c=>char.IsControl(c)))throw new ArgumentException("Passwords require 15 to 128 characters without control characters.");try{_=new UTF8Encoding(false,true).GetByteCount(value);}catch(EncoderFallbackException){throw new ArgumentException("Invalid password Unicode.");}}
    public static string Actor(OperatorAccount account)=>$"{account.UserName} ({account.Id:D})";
}
