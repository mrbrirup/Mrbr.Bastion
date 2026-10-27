using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Mrbr.Bastion.Configuration;
using Mrbr.Bastion.Hosting;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Notifications.Smtp;
using Mrbr.Bastion.Notifications.Webhooks;
using Mrbr.Bastion.Server;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class ConfigurationTests
{
    private static LauncherProfile Profile(TestLedger temporary) => new() { DeploymentDirectory = temporary.DirectoryPath };
    private static void Keys(LauncherProfile p)
    { PemKeyService.CreatePair(p, p.Keys.Receiver); PemKeyService.CreatePair(p, p.Keys.Node); PemKeyService.ApplyPaths(p); }

    [Fact]
    public void ProfileAndRuntimeExportRoundTripSettingsWithoutPersistingSecrets()
    {
        using var temp = new TestLedger(); var p = Profile(temp);
        p.Receiver.Bastion.Software.NvdApiKey = "fixture-nvd-secret";
        p.Receiver.Kestrel.Endpoints.Https.Certificate.Password = "fixture-pfx-secret";
        p.Receiver.Bastion.Notifications.Email = [new() { RouteId = "email", Host = "smtp.example.test", From = "a@example.test", To = "b@example.test", Username = "fixture-user", Password = "fixture-smtp-secret" }];
        p.Receiver.Bastion.Notifications.Webhooks = [new() { RouteId = "hook", Endpoint = new("https://example.test/hook"), BearerToken = "fixture-bearer-secret", SigningKey = "fixture-webhook-secret-with-32-characters" }];
        p.Inventory.ProcessEvents = true;
        p.Collector.MaximumStoredPayloadBytes=1024L*1024*1024;
        p.Collector.Retention=new(){Enabled=true,ArchiveDirectory="archives",KeepRecentBlocks=64,MinimumAgeSeconds=120};
        p.Inventory.Retention=new(){Enabled=true,ArchiveDirectory="inventory-archives",KeepRecentBlocks=32};
        p.Collector.QueueCapacity = 16384; p.Collector.BatchSize = 250;
        p.Collector.FlushIntervalMilliseconds = 500; p.Collector.EtwBufferSizeMegabytes = 128;
        p.Collector.ExcludeManagedProcessFileIo = false;
        p.SelectedRunDurationSeconds = 120;
        p.Inventory.Crawlers = [new() { Id = "applications", Root = temp.DirectoryPath, Enabled = false }];
        string path = p.Resolve("desktop.bastion.local.json"); ProfileStorage.Save(path, p); ProfileStorage.Export(p);
        foreach (string file in new[] { path, p.ReceiverFile, p.InventoryFile, p.RetentionFile })
        {
            string text = File.ReadAllText(file);
            foreach (string secret in ProfileStorage.ReceiverSecrets(p.Receiver).Values) Assert.DoesNotContain(secret, text);
        }
        var loaded = ProfileStorage.Load(path);
        Assert.True(loaded.Inventory.ProcessEvents); Assert.Single(loaded.Inventory.Crawlers);
        Assert.Equal(16384, loaded.Collector.QueueCapacity); Assert.Equal(250, loaded.Collector.BatchSize);
        Assert.Equal(500, loaded.Collector.FlushIntervalMilliseconds); Assert.Equal(128, loaded.Collector.EtwBufferSizeMegabytes);
        Assert.False(loaded.Collector.ExcludeManagedProcessFileIo);
        Assert.Equal(120, loaded.SelectedRunDurationSeconds);
        Assert.Equal(p.Collector.MaximumStoredPayloadBytes,loaded.Collector.MaximumStoredPayloadBytes);
        Assert.Equal(p.Collector.Retention,loaded.Collector.Retention);
        Assert.Equal(p.Inventory.Retention,loaded.Inventory.Retention);
        Assert.Equal(p.Collector.Retention,JsonSerializer.Deserialize<Mrbr.Bastion.Cache.CacheRetentionOptions>(File.ReadAllText(p.RetentionFile),ProfileStorage.Json));
        Assert.Null(loaded.Receiver.Bastion.Software.NvdApiKey);
        Assert.Null(Assert.Single(loaded.Receiver.Bastion.Notifications.Email).Password);
        Assert.Equal("fixture-user", loaded.Receiver.Bastion.Notifications.Email[0].Username);
        var host = new ConfigurationBuilder().AddJsonFile(p.ReceiverFile).Build().GetSection("Bastion").Get<ServerSettings>()!;
        Assert.True(host.Dashboard.Enabled); Assert.True(host.Software.Enabled); Assert.Equal("hook", Assert.Single(host.Notifications.Webhooks).RouteId);
        var inventory = JsonSerializer.Deserialize<Mrbr.Bastion.Inventory.Agent.InventoryAgentSettings>(File.ReadAllText(p.InventoryFile), InventoryJson.Options)!;
        inventory.Validate(); Assert.True(inventory.ProcessEvents);
        var variables = ProfileStorage.ReceiverSecrets(p.Receiver);
        Assert.Equal("fixture-pfx-secret", variables["Kestrel__Endpoints__Https__Certificate__Password"]);
        Assert.Equal("fixture-smtp-secret", variables["Bastion__Notifications__Email__0__Password"]);
        Assert.Equal("fixture-bearer-secret", variables["Bastion__Notifications__Webhooks__0__BearerToken"]);
    }

    [Fact]
    public void PemCreationProducesUsableMatchingKeysAndRefusesOverwrite()
    {
        using var temp = new TestLedger(); var p = Profile(temp); var pair = p.Keys.Node;
        string fingerprint = PemKeyService.CreatePair(p, pair);
        Assert.Equal(64, fingerprint.Length); Assert.Equal(fingerprint, PemKeyService.VerifyPair(p, pair));
        string privatePem = File.ReadAllText(p.Resolve(pair.PrivateKeyPath));
        string publicPem = File.ReadAllText(p.Resolve(pair.PublicKeyPath));
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", privatePem); Assert.StartsWith("-----BEGIN PUBLIC KEY-----", publicPem);
        Assert.Throws<IOException>(() => PemKeyService.CreatePair(p, pair));
        Assert.Equal(privatePem, File.ReadAllText(p.Resolve(pair.PrivateKeyPath)));
        Assert.Equal(publicPem, File.ReadAllText(p.Resolve(pair.PublicKeyPath)));
        var collision = new PemKeyPair { PrivateKeyPath = "same.pem", PublicKeyPath = "same.pem" };
        Assert.Throws<IOException>(() => PemKeyService.CreatePair(p, collision));
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(p.Resolve(pair.PublicKeyPath), wrongKey.ExportSubjectPublicKeyInfoPem());
        Assert.Throws<CryptographicException>(() => PemKeyService.VerifyPair(p, pair));
    }

    [Fact]
    public async Task InitializationEnrollsTwoDistinctStableLedgersWithoutResettingExistingData()
    {
        using var temp = new TestLedger(); var p = Profile(temp); Keys(p);
        var first = await ConfigurationActions.InitializeLedgersAsync(p);
        Assert.Equal(2, first.Length); Assert.NotEqual(first[0].LedgerId, first[1].LedgerId);
        Assert.Equal(first, await ConfigurationActions.InitializeLedgersAsync(p));
        Assert.Equal(2, p.Receiver.Bastion.Nodes.Length);
        using var receiver = ServerKeyMaterial.Load(p.Receiver.Bastion, p.DeploymentDirectory);
        ProfileStorage.Export(p); Assert.True(File.Exists(p.Resolve(p.Collector.CacheDatabasePath)));
    }

    [Fact]
    public async Task BootstrapCreatesOneAdministratorAndCannotReplaceExistingAccounts()
    {
        using var temp = new TestLedger(); var p = Profile(temp);
        await ConfigurationActions.BootstrapAdministratorAsync(p, "desktop-admin", "fixture long password 123");
        await Assert.ThrowsAnyAsync<Exception>(() => ConfigurationActions.BootstrapAdministratorAsync(p, "another-admin", "fixture long password 456"));
        await using var store = Mrbr.Bastion.Operators.Sqlite.SqliteOperatorStore.Open(new() { DatabasePath = p.Resolve("data/operators.db") });
        Assert.Equal("desktop-admin", Assert.Single((await store.ReadUsersAsync()).Users).UserName);
    }

    [Fact]
    public void RunPlansUseArgumentListsAndKeepSecretsOutOfArguments()
    {
        using var temp = new TestLedger(); var p = Profile(temp); Directory.CreateDirectory(p.DeploymentDirectory);
        string executable = p.Resolve("a path with spaces/server.dll"); Directory.CreateDirectory(Path.GetDirectoryName(executable)!); File.WriteAllText(executable, "fixture");
        p.Runtime.ReceiverExecutable = executable; p.Receiver.Bastion.Software.NvdApiKey = "fixture-nvd-secret";
        var plan = RunPlan.Create(p, RunTarget.Receiver);
        Assert.Equal(executable, plan.Arguments[0]); Assert.Equal(p.ReceiverFile, plan.Arguments[2]);
        Assert.DoesNotContain("fixture-nvd-secret", string.Join(' ', plan.Arguments)); Assert.Contains("fixture-nvd-secret", plan.Environment.Values);
        p.Runtime.CollectorExecutable = executable; p.Collector.ExcludeManagedProcessFileIo = false;
        p.Collector.QueueCapacity = 32768;
        var collector = RunPlan.Create(p, RunTarget.Collector);
        Assert.Contains("--include-managed-file-io", collector.Arguments);
        Assert.Equal("32768", collector.Arguments[Array.IndexOf(collector.Arguments, "--queue-capacity") + 1]);
        Assert.Equal(p.RetentionFile,collector.Arguments[Array.IndexOf(collector.Arguments,"--retention-config")+1]);
        Assert.Equal(p.Collector.MaximumStoredPayloadBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),collector.Arguments[Array.IndexOf(collector.Arguments,"--cache-capacity-bytes")+1]);
        p.Inventory.CacheDatabasePath = p.Collector.CacheDatabasePath;
        Assert.Throws<ArgumentException>(() => ConfigurationActions.Validate(p, false));
    }

    [Fact]
    public async Task ControlPipeRejectsWrongTokenAndAcceptsAnAuthenticatedStop()
    {
        string pipe = "bastion-test-" + Guid.NewGuid().ToString("N"), token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var listener = new LocalProcessControl(pipe, token, () => stopped.TrySetResult());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await Assert.ThrowsAnyAsync<IOException>(() => LocalProcessControl.RequestStopAsync(pipe, new string('0', 64), timeout.Token));
        Assert.False(stopped.Task.IsCompleted);
        await LocalProcessControl.RequestStopAsync(pipe, token, timeout.Token);
        await stopped.Task.WaitAsync(timeout.Token);
    }

    [Fact]
    public async Task ManagedProcessStopsGracefullyWithoutForceTermination()
    {
        using var temp = new TestLedger(); Directory.CreateDirectory(temp.DirectoryPath);
        string tests = typeof(ConfigurationTests).Assembly.Location;
        var runner = new ManagedProcesses();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        runner.Output += line => { if (line.Contains("CONTROL READY", StringComparison.Ordinal)) ready.TrySetResult(); if (line.Contains("CONTROL STOPPED", StringComparison.Ordinal)) stopped.TrySetResult(); };
        runner.Changed += () => { if (!runner.AnyRunning) exited.TrySetResult(); };
        runner.Start(RunTarget.Receiver, new("dotnet", ["exec", "--runtimeconfig", Path.ChangeExtension(tests, "runtimeconfig.json"),
            "--depsfile", Path.ChangeExtension(tests, "deps.json"), typeof(Mrbr.Bastion.CrashProbe.Program).Assembly.Location, "--desktop-control"], temp.DirectoryPath, []));
        try
        {
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(15));
            await runner.StopAllAsync(); await stopped.Task.WaitAsync(TimeSpan.FromSeconds(5)); await exited.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(runner.AnyRunning);
        }
        finally { if (runner.AnyRunning) { runner.ForceStop(RunTarget.Receiver); await exited.Task.WaitAsync(TimeSpan.FromSeconds(10)); } }
    }

    [Fact]
    public async Task FileIoPolicyUpdatesRequireAuthenticationAndDoNotDisableShutdown()
    {
        string pipe = "bastion-test-" + Guid.NewGuid().ToString("N"), token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); string? applied = null;
        await using var listener = new LocalProcessControl(pipe, token, () => stopped.TrySetResult(), policy =>
        { if (policy != "[]") throw new ArgumentException("Invalid test policy"); applied = policy; });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await Assert.ThrowsAnyAsync<IOException>(() => LocalProcessControl.UpdateFileIoAsync(pipe, new string('0', 64), "[]", timeout.Token));
        Assert.Null(applied);
        await Assert.ThrowsAnyAsync<IOException>(() => LocalProcessControl.UpdateFileIoAsync(pipe, token, "invalid", timeout.Token));
        await LocalProcessControl.UpdateFileIoAsync(pipe, token, "[]", timeout.Token);
        Assert.Equal("[]", applied); Assert.False(stopped.Task.IsCompleted);
        await Assert.ThrowsAsync<ArgumentException>(() => LocalProcessControl.UpdateFileIoAsync(pipe, token, new string('x', 8193), timeout.Token));
        await LocalProcessControl.RequestStopAsync(pipe, token, timeout.Token);
        await stopped.Task.WaitAsync(timeout.Token);
    }

    [Fact]
    public async Task StartingAPeerRefreshesTheRunningCollectorsExplicitLifetimeScope()
    {
        using var temp = new TestLedger(); Directory.CreateDirectory(temp.DirectoryPath);
        var runner = new ManagedProcesses();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var initial = new TaskCompletionSource<Mrbr.Bastion.Core.FileIoProcessIdentity[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var changed = new TaskCompletionSource<Mrbr.Bastion.Core.FileIoProcessIdentity[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        runner.Output += line =>
        {
            if (line == "[Collector] CONTROL READY") ready.TrySetResult();
            const string first = "[Collector] INITIAL POLICY ", update = "[Collector] FILE POLICY ";
            if (line.StartsWith(first, StringComparison.Ordinal)) initial.TrySetResult(JsonSerializer.Deserialize<Mrbr.Bastion.Core.FileIoProcessIdentity[]>(line[first.Length..])!);
            if (line.StartsWith(update, StringComparison.Ordinal)) changed.TrySetResult(JsonSerializer.Deserialize<Mrbr.Bastion.Core.FileIoProcessIdentity[]>(line[update.Length..])!);
        };
        RunPlan Probe(string mode)
        {
            string tests = typeof(ConfigurationTests).Assembly.Location;
            return new("dotnet", ["exec", "--runtimeconfig", Path.ChangeExtension(tests, "runtimeconfig.json"),
                "--depsfile", Path.ChangeExtension(tests, "deps.json"), typeof(Mrbr.Bastion.CrashProbe.Program).Assembly.Location, mode], temp.DirectoryPath, []);
        }
        try
        {
            await runner.StartAsync(RunTarget.Collector, Probe("--desktop-control-policy"));
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(Environment.ProcessId, Assert.Single(await initial.Task.WaitAsync(TimeSpan.FromSeconds(5))).ProcessId);
            await runner.StartAsync(RunTarget.Receiver, Probe("--desktop-control"));
            var policy = await changed.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(3, policy.Length); Assert.Contains(policy, p => p.ProcessId == Environment.ProcessId);
            Assert.Equal(3, policy.Select(p => p.ProcessId).Distinct().Count()); Assert.All(policy, p => Assert.True(p.StartedUtcTicks > 0));
            await runner.StopAllAsync(); Assert.False(runner.AnyRunning);
        }
        finally
        {
            if (runner.AnyRunning) foreach (var target in Enum.GetValues<RunTarget>()) runner.ForceStop(target);
        }
    }
}
