using System.Text.Json;
using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.Security;
using Mrbr.Bastion.Operators.Sqlite;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class OperatorStoreTests
{
    [Fact]
    public void PasswordHashesAreSaltedVersionedAndRejectMalformedOrExcessiveWork()
    {
        var passwords=new OperatorPasswords();string first=passwords.Hash(OperatorFixture.Password),second=passwords.Hash(OperatorFixture.Password);
        Assert.NotEqual(first,second);Assert.DoesNotContain(OperatorFixture.Password,first);Assert.True(passwords.Verify(first,OperatorFixture.Password));Assert.False(passwords.Verify(first,"incorrect password"));
        Assert.Throws<InvalidDataException>(()=>passwords.Verify(first.Replace(":600000:",":999999999:"),OperatorFixture.Password));
        Assert.Throws<InvalidDataException>(()=>passwords.Verify("invalid",OperatorFixture.Password));Assert.Throws<ArgumentException>(()=>passwords.Hash("short"));Assert.Throws<ArgumentException>(()=>passwords.Hash(new string('p',129)));
    }
    [Theory][InlineData(OperatorRole.Viewer,false,false,false)][InlineData(OperatorRole.Operator,true,true,false)][InlineData(OperatorRole.Analyst,true,false,true)][InlineData(OperatorRole.Administrator,true,true,true)]
    public void RolesHaveAnExplicitPermissionMatrix(OperatorRole role,bool evidence,bool acknowledge,bool review)
    {
        var permissions=OperatorPermissions.ForRoles([role]);Assert.Contains(OperatorPermissions.Read,permissions);
        Assert.Equal(evidence,permissions.Contains(OperatorPermissions.Evidence));Assert.Equal(acknowledge,permissions.Contains(OperatorPermissions.Acknowledge));Assert.Equal(review,permissions.Contains(OperatorPermissions.Review));
        Assert.Equal(role==OperatorRole.Administrator,permissions.Contains(OperatorPermissions.ManageUsers));
    }
    [Fact]
    public async Task UsersAndSessionsPersistButPasswordsAndSecurityStampsAreNeverSerialized()
    {
        await using var f=await OperatorFixture.CreateAsync();var user=await f.CreateUserAsync("ReadOnly",[OperatorRole.Viewer]);var session=await f.LoginAsync("READONLY");Assert.NotNull(session);
        await f.ReopenAsync();Assert.NotNull(await f.Store.ReadSessionAsync(session.Id,user.Id,session.SecurityStamp,f.Clock.GetUtcNow()));
        var page=await f.Store.ReadUsersAsync();Assert.Equal(2,page.Users.Length);var credentials=(await f.Store.FindByIdAsync(user.Id))!;
        string output=JsonSerializer.Serialize(new{page,credentials,session},OperatorValidation.Json);Assert.DoesNotContain("passwordHash",output);Assert.DoesNotContain("securityStamp",output);Assert.DoesNotContain(OperatorFixture.Password,output);
        await Assert.ThrowsAsync<OperatorConflictException>(()=>f.Accounts.CreateAsync("READONLY","Duplicate",[OperatorRole.Viewer],OperatorFixture.Password,f.Actor));
        Assert.Throws<IOException>(()=>SqliteOperatorStore.Open(new(){DatabasePath=f.DatabasePath}));
    }
    [Fact]
    public async Task RepeatedFailuresLockAccountsAcrossRestartAndExpireWithoutBypassingPasswordChecks()
    {
        await using var f=await OperatorFixture.CreateAsync();for(int i=0;i<5;i++)Assert.Null(await f.LoginAsync(password:"wrong-password-value"));
        Assert.NotNull((await f.Store.FindByIdAsync(f.Admin.Id))!.LockedUntilUtc);await f.ReopenAsync();Assert.Null(await f.LoginAsync());
        f.Clock.Advance(TimeSpan.FromMinutes(6));Assert.Null(await f.LoginAsync(password:"still incorrect"));Assert.NotNull(await f.LoginAsync());
        Assert.Equal(0,(await f.Store.FindByIdAsync(f.Admin.Id))!.FailedAttempts);
        Assert.Contains((await f.Store.ReadSecurityAsync()).Events,e=>e.Action=="LoginRejected");
    }
    [Fact]
    public async Task RoleChangesAndDisableRevokeSessionsAndEnforceOptimisticConcurrency()
    {
        await using var f=await OperatorFixture.CreateAsync();var user=await f.CreateUserAsync("responder",[OperatorRole.Operator]);var session=(await f.LoginAsync(user.UserName))!;
        var changed=await f.Store.UpdateAsync(user.Id,user.Revision,"Renamed responder",[OperatorRole.Viewer],true,f.Actor,f.Clock.GetUtcNow());
        Assert.Null(await f.Store.ReadSessionAsync(session.Id,user.Id,session.SecurityStamp,f.Clock.GetUtcNow()));Assert.Equal(user.Revision+1,changed.Revision);
        await Assert.ThrowsAsync<OperatorConflictException>(()=>f.Store.UpdateAsync(user.Id,user.Revision,"Old revision",[OperatorRole.Administrator],true,f.Actor,f.Clock.GetUtcNow()));
        await f.Store.UpdateAsync(user.Id,changed.Revision,changed.DisplayName,changed.Roles,false,f.Actor,f.Clock.GetUtcNow());Assert.Null(await f.LoginAsync(user.UserName));
    }
    [Fact]
    public async Task LastAdministratorCannotBeDemotedOrDisabledAndStaleActorsCannotAdministerUsers()
    {
        await using var f=await OperatorFixture.CreateAsync();
        Assert.Equal("LastAdministrator",(await Assert.ThrowsAsync<OperatorConflictException>(()=>f.Store.UpdateAsync(f.Admin.Id,1,"Admin",[OperatorRole.Viewer],true,f.Actor,f.Clock.GetUtcNow()))).Code);
        await Assert.ThrowsAsync<OperatorConflictException>(()=>f.Store.UpdateAsync(f.Admin.Id,1,"Admin",[OperatorRole.Administrator],false,f.Actor,f.Clock.GetUtcNow()));
        await f.Store.RevokeAllAsync(f.Admin.Id,1,f.Actor,f.Clock.GetUtcNow());await Assert.ThrowsAsync<OperatorAccessException>(()=>f.CreateUserAsync("blocked",[OperatorRole.Viewer]));
        Assert.Single((await f.Store.ReadUsersAsync()).Users);
    }
    [Fact]
    public async Task PasswordChangesRevokeAllSessionsAndClearForcedChangeState()
    {
        await using var f=await OperatorFixture.CreateAsync();var user=await f.CreateUserAsync("temporary",[OperatorRole.Viewer],mustChange:true);var first=(await f.LoginAsync(user.UserName))!;var second=(await f.LoginAsync(user.UserName))!;
        Assert.True(first.Account.MustChangePassword);Assert.True(await f.Accounts.ChangePasswordAsync(new(user.Id,first.SecurityStamp),OperatorFixture.Password,"replacement-password-for-fixture"));
        Assert.Null(await f.Store.ReadSessionAsync(first.Id,user.Id,first.SecurityStamp,f.Clock.GetUtcNow()));Assert.Null(await f.Store.ReadSessionAsync(second.Id,user.Id,second.SecurityStamp,f.Clock.GetUtcNow()));
        Assert.Null(await f.LoginAsync(user.UserName));var replacement=(await f.LoginAsync(user.UserName,"replacement-password-for-fixture"))!;Assert.False(replacement.Account.MustChangePassword);
    }
    [Fact]
    public async Task SecurityHistoryFailureRollsBackSecurityChangesAndRevocation()
    {
        await using var f=await OperatorFixture.CreateAsync(maximumEvents:2);var session=(await f.LoginAsync())!;
        await Assert.ThrowsAsync<IOException>(()=>f.Store.UpdateAsync(f.Admin.Id,1,"Changed",[OperatorRole.Administrator],true,f.Actor,f.Clock.GetUtcNow()));
        Assert.NotNull(await f.Store.ReadSessionAsync(session.Id,f.Admin.Id,session.SecurityStamp,f.Clock.GetUtcNow()));Assert.Equal(1,(await f.Store.FindByIdAsync(f.Admin.Id))!.Account.Revision);
    }
    [Fact]
    public async Task SignOutRevokesOnlyTheSelectedSessionAndTimeRollbackCannotExtendSessions()
    {
        await using var f=await OperatorFixture.CreateAsync();var first=(await f.LoginAsync())!;var second=(await f.LoginAsync())!;
        await f.Store.RevokeSessionAsync(first.Id,f.Admin.Id,f.Clock.GetUtcNow());Assert.Null(await f.Store.ReadSessionAsync(first.Id,f.Admin.Id,first.SecurityStamp,f.Clock.GetUtcNow()));
        Assert.NotNull(await f.Store.ReadSessionAsync(second.Id,f.Admin.Id,second.SecurityStamp,f.Clock.GetUtcNow()));
        Assert.Null(await f.Store.ReadSessionAsync(second.Id,f.Admin.Id,second.SecurityStamp,f.Clock.GetUtcNow().AddSeconds(-1)));f.Clock.Advance(TimeSpan.FromHours(9));Assert.Null(await f.Store.ReadSessionAsync(second.Id,f.Admin.Id,second.SecurityStamp,f.Clock.GetUtcNow()));
    }
    [Fact]
    public async Task BootstrapAndLocalRecoveryAreExplicitAuditedAndNeverReuseAUserIdentity()
    {
        await using var f=await OperatorFixture.CreateAsync();await Assert.ThrowsAsync<OperatorConflictException>(()=>f.Accounts.CreateAsync("other-admin","Other",[OperatorRole.Administrator],OperatorFixture.Password,bootstrap:true));
        var before=(await f.LoginAsync())!;await f.Accounts.RecoverAsync("admin","recovery-password-for-fixture");Assert.Null(await f.Store.ReadSessionAsync(before.Id,f.Admin.Id,before.SecurityStamp,f.Clock.GetUtcNow()));
        var recovered=(await f.Accounts.LoginAsync("admin","recovery-password-for-fixture",null,TimeSpan.FromHours(8)))!;Assert.True(recovered.Account.MustChangePassword);Assert.Equal(f.Admin.Id,recovered.Account.Id);
        Assert.Contains((await f.Store.ReadSecurityAsync()).Events,e=>e.Action=="AdministratorRecoveredLocally");
    }
    [Fact]
    public async Task ConcurrentAdministratorChangesCannotDisableTheLastAdministrator()
    {
        await using var f=await OperatorFixture.CreateAsync();var second=await f.CreateUserAsync("second-admin",[OperatorRole.Administrator]);var secondActor=new OperatorActor(second.Id,(await f.Store.FindByIdAsync(second.Id))!.SecurityStamp);
        async Task<string> Disable(OperatorAccount account,OperatorActor actor)
        {try{await f.Store.UpdateAsync(account.Id,account.Revision,account.DisplayName,account.Roles,false,actor,f.Clock.GetUtcNow());return "Disabled";}catch(OperatorConflictException e){return e.Code;}}
        var outcomes=await Task.WhenAll(Disable(f.Admin,f.Actor),Disable(second,secondActor));Assert.Contains("Disabled",outcomes);Assert.Contains("LastAdministrator",outcomes);
        Assert.Single((await f.Store.ReadUsersAsync()).Users,u=>u.Enabled&&u.Roles.Contains(OperatorRole.Administrator));
    }
}
