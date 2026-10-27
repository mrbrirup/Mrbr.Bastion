using Mrbr.Bastion.Operators;
using Mrbr.Bastion.Operators.Security;
using Mrbr.Bastion.Operators.Sqlite;

if(args.Length==0||args.Contains("--help"))
{Console.WriteLine("Usage: Mrbr.Bastion.Operators.Tool bootstrap|recover-admin <operators.db> <username> [--password-stdin]\n       Mrbr.Bastion.Operators.Tool list <operators.db>\nStop the server before opening its operator database. Bootstrap works only on an empty store. Recovery restores a named administrator, revokes sessions and requires a password change. Passwords are prompted without echo; they are never command-line arguments.");return 0;}
if(args.Length is <2 or >4||args[0] is not("bootstrap" or "recover-admin" or "list")||args[0]=="list"&&args.Length!=2||args[0]!="list"&&(args.Length<3||args.Length==4&&args[3]!="--password-stdin")){Console.Error.WriteLine("Use --help for usage.");return 1;}
try
{
    if(args[0]!="bootstrap"&&!File.Exists(args[1]))throw new FileNotFoundException("The existing operator database is missing.");
    await using var store=SqliteOperatorStore.Open(new(){DatabasePath=args[1]});
    if(args[0]=="list")
    {string? cursor=null;do{var page=await store.ReadUsersAsync(cursor,100);foreach(var user in page.Users)Console.WriteLine($"{user.UserName}\t{user.Id:D}\t{string.Join(',',user.Roles)}\tenabled={user.Enabled}\tchange-password={user.MustChangePassword}");cursor=page.NextAfter;}while(cursor is not null);return 0;}
    string password;
    if(args.Contains("--password-stdin"))password=await Console.In.ReadLineAsync()??throw new ArgumentException("Password input missing.");
    else
    {
        if(Console.IsInputRedirected)throw new ArgumentException("Use --password-stdin for redirected input.");
        string ReadSecret(string prompt){Console.Write(prompt);var chars=new List<char>();while(true){var key=Console.ReadKey(true);if(key.Key==ConsoleKey.Enter)break;if(key.Key==ConsoleKey.Backspace){if(chars.Count>0)chars.RemoveAt(chars.Count-1);}else if(!char.IsControl(key.KeyChar)){if(chars.Count>=128)throw new ArgumentException("Password is too long.");chars.Add(key.KeyChar);}}Console.WriteLine();return new(chars.ToArray());}
        password=ReadSecret("Password: ");if(password!=ReadSecret("Confirm password: "))throw new ArgumentException("Passwords do not match.");
    }
    var service=new OperatorAccounts(store);
    if(args[0]=="bootstrap")await service.CreateAsync(args[2],args[2],[OperatorRole.Administrator],password,bootstrap:true);
    else await service.RecoverAsync(args[2],password);
    Console.WriteLine("Operator identity updated. Security history was retained; no password was printed.");return 0;
}catch(Exception e){Console.Error.WriteLine(e is OperatorConflictException conflict?conflict.Code:e.Message);return 1;}
