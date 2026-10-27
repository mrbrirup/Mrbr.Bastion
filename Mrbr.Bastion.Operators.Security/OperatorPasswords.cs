using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Mrbr.Bastion.Operators.Security;

/// <summary>Versioned PBKDF2-HMAC-SHA256 with random salts, bounded work and constant-time digest comparison.</summary>
public sealed class OperatorPasswords
{
    private const string Format="bastion.pbkdf2-sha256.v1";
    public const int Iterations=600000;
    public string Hash(string password)
    {
        OperatorValidation.Password(password);byte[] salt=RandomNumberGenerator.GetBytes(16),bytes=Encoding.UTF8.GetBytes(password);
        try{return $"{Format}:{Iterations}:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(bytes,salt,Iterations,HashAlgorithmName.SHA256,32))}";}
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    public bool Verify(string hash,string password)
    {
        if(hash.Length>256)throw new InvalidDataException("Invalid password hash.");var parts=hash.Split(':');
        if(parts.Length!=4||parts[0]!=Format||!int.TryParse(parts[1],NumberStyles.None,CultureInfo.InvariantCulture,out int iterations)||iterations is <Iterations or >2000000)throw new InvalidDataException("Unsupported password hash.");
        byte[] salt,digest;try{salt=Convert.FromBase64String(parts[2]);digest=Convert.FromBase64String(parts[3]);}catch(FormatException e){throw new InvalidDataException("Invalid password hash encoding.",e);}
        if(salt.Length!=16||digest.Length!=32)throw new InvalidDataException("Invalid password hash sizes.");
        if(password.Length>128)return false;
        byte[] bytes;try{bytes=new UTF8Encoding(false,true).GetBytes(password);}catch(EncoderFallbackException){return false;}
        try{return CryptographicOperations.FixedTimeEquals(digest,Rfc2898DeriveBytes.Pbkdf2(bytes,salt,iterations,HashAlgorithmName.SHA256,32));}
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
}
public sealed class OperatorAccounts
{
    private readonly IOperatorStore _store;private readonly OperatorPasswords _passwords;private readonly TimeProvider _clock;private readonly string _dummy;
    private readonly SemaphoreSlim _work=new(4,4);
    public OperatorAccounts(IOperatorStore store,OperatorPasswords? passwords=null,TimeProvider? clock=null)
    {_store=store;_passwords=passwords??new();_clock=clock??TimeProvider.System;_dummy=_passwords.Hash(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));}
    public async Task<OperatorSession?> LoginAsync(string name,string password,string? remote,TimeSpan lifetime,CancellationToken ct=default)
    {
        if(name.Length>64||password.Length>128)return null;
        await _work.WaitAsync(ct);try
        {
            string normalized;try{normalized=OperatorValidation.Name(name);}catch(ArgumentException){normalized="";}
            var user=await _store.FindCredentialsAsync(normalized,ct);bool matches=_passwords.Verify(user?.PasswordHash??_dummy,password);
            return await _store.RecordLoginAsync(normalized,user?.SecurityStamp,matches,remote,_clock.GetUtcNow(),lifetime,ct);
        }finally{_work.Release();}
    }
    public async Task<OperatorAccount> CreateAsync(string name,string display,OperatorRole[] roles,string password,OperatorActor? actor=null,bool bootstrap=false,CancellationToken ct=default)
    {
        OperatorValidation.Name(name);OperatorValidation.Display(display);OperatorValidation.Roles(roles);OperatorValidation.Password(password);
        await _work.WaitAsync(ct);try{return await _store.CreateAsync(name,display,roles,_passwords.Hash(password),!bootstrap,actor,bootstrap,_clock.GetUtcNow(),ct);}finally{_work.Release();}
    }
    public async Task ResetPasswordAsync(Guid id,long revision,string password,OperatorActor actor,CancellationToken ct=default)
    {OperatorValidation.Password(password);await _work.WaitAsync(ct);try{await _store.ResetPasswordAsync(id,revision,_passwords.Hash(password),actor,_clock.GetUtcNow(),ct);}finally{_work.Release();}}
    public async Task<bool> ChangePasswordAsync(OperatorActor actor,string current,string replacement,CancellationToken ct=default)
    {
        OperatorValidation.Password(replacement);if(current.Length>128)return false;
        await _work.WaitAsync(ct);try{var user=await _store.FindByIdAsync(actor.UserId,ct);bool valid=_passwords.Verify(user?.PasswordHash??_dummy,current);if(user is null||!valid||user.SecurityStamp!=actor.SecurityStamp)return false;
            if(_passwords.Verify(user.PasswordHash,replacement))throw new ArgumentException("Choose a different password.");
            return await _store.ChangePasswordAsync(actor,user.PasswordHash,_passwords.Hash(replacement),_clock.GetUtcNow(),ct);
        }finally{_work.Release();}
    }
    public async Task RecoverAsync(string name,string password,CancellationToken ct=default)
    {OperatorValidation.Name(name);OperatorValidation.Password(password);await _work.WaitAsync(ct);try{await _store.RecoverAdministratorAsync(name,_passwords.Hash(password),_clock.GetUtcNow(),ct);}finally{_work.Release();}}
}
