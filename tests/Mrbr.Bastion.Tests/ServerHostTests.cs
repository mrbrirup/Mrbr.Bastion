using System.Diagnostics;
using System.Text.Json;
using Mrbr.Bastion.Server;
using Mrbr.Bastion.Transport;
using Mrbr.Bastion.Transport.Http;
using Xunit;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Auditing;
using Mrbr.Bastion.Auditing.Agent;
using Mrbr.Bastion.Auditing.Contracts;
using Mrbr.Bastion.Auditing.Sqlite;
using Mrbr.Bastion.Notifications.Sqlite;
using Microsoft.Data.Sqlite;

namespace Mrbr.Bastion.Tests;

public sealed class ServerHostTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConfiguredExecutablePersistsTelemetryAuditsAndNotificationsAcrossProcessTermination(bool dashboardEnabled)
    {
        await using var f = await IngestionFixture.CreateAsync();
        await using var webhook = await NotificationWebhookHost.StartAsync((call, _) => Task.FromResult<Microsoft.AspNetCore.Http.IResult>(
            call == 1 ? Microsoft.AspNetCore.Http.Results.StatusCode(503) : Microsoft.AspNetCore.Http.Results.Ok()));
        await f.Store.DisposeAsync();
        File.WriteAllText(Path.Combine(f.Local.DirectoryPath, "node-public.pem"), f.Local.NodeKey.ExportSubjectPublicKeyInfoPem());
        File.WriteAllText(Path.Combine(f.Local.DirectoryPath, "receiver-private.pem"), f.Local.ServerKey.ExportPkcs8PrivateKeyPem());
        string configPath = Path.Combine(f.Local.DirectoryPath, "server.json");
        File.WriteAllText(configPath, JsonSerializer.Serialize(new
        {
            Kestrel = new { Endpoints = new { Test = new { Url = "http://127.0.0.1:0", Protocols = "Http1" } } },
            Bastion = new ServerSettings
            {
                DatabasePath = "central.db", ReceiptSigningPrivateKeyPath = "receiver-private.pem", ReceiptSigningKeyId = "server-key",
                AllowInsecureLoopback = true,
                Dashboard = new() { Enabled = dashboardEnabled, AuthenticationMode=Mrbr.Bastion.Operators.AspNetCore.OperatorAuthenticationMode.LegacyToken, AccessToken = DashboardTestHost.Token, AlertEvaluationIntervalSeconds = 1 },
                Notifications = new()
                {
                    Enabled = true, PollIntervalSeconds = 1, InitialRetryDelaySeconds = 1, MaximumRetryDelaySeconds = 1,
                    Webhooks = [new() { RouteId = "process-test", Endpoint = webhook.Endpoint, AllowInsecureLoopback = true }]
                },
                Nodes = [new() { NodeId = f.First.Content.NodeId, LedgerId = f.First.Content.LedgerId,
                    PublicKeys = [new() { Path = "node-public.pem", KeyId = "node-key" }] }]
            }
        }));
        string tests = typeof(ServerHostTests).Assembly.Location;
        var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in new[] { "exec", "--runtimeconfig", Path.ChangeExtension(tests, "runtimeconfig.json"),
            "--depsfile", Path.ChangeExtension(tests, "deps.json"), typeof(ServerSettings).Assembly.Location, "--config", configPath }) start.ArgumentList.Add(argument);
        foreach (string name in start.Environment.Keys.Where(k => k.StartsWith("Bastion__", StringComparison.OrdinalIgnoreCase)
            || k.StartsWith("Kestrel__", StringComparison.OrdinalIgnoreCase)).ToArray()) start.Environment.Remove(name);
        using var child = Process.Start(start)!;
        var standardError = child.StandardError.ReadToEndAsync();
        var startupOutput = new System.Text.StringBuilder();
        Mrbr.Bastion.Abstraction.SettlementReceipt receipt;
        SignedAuditResult auditResult;
        try
        {
            Uri? address = null;
            using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            while (address is null)
            {
                string? line;
                try { line = await child.StandardOutput.ReadLineAsync(startup.Token); }
                catch (OperationCanceledException)
                {
                    if (!child.HasExited) child.Kill(entireProcessTree: true);
                    await child.WaitForExitAsync();
                    throw new IOException("The configured server failed startup: " + startupOutput + await standardError);
                }
                if (line is null) throw new IOException("The configured server failed startup: " + startupOutput + await standardError);
                startupOutput.AppendLine(line);
                const string marker = "Now listening on: ";
                int index = line.IndexOf(marker, StringComparison.Ordinal);
                if (index >= 0) address = new Uri(line[(index + marker.Length)..].Trim());
            }
            var remainingOutput = child.StandardOutput.ReadToEndAsync();
            using var transport = new HttpTelemetryTransport(address, f.Local.Server, new() { AllowInsecureLoopback = true });
            receipt = await transport.SubmitAsync(f.First);
            await f.Cache.ReconcileAsync(receipt);
            using var auditTransport = new HttpHeartbeatAuditTransport(address, f.Local.Server, new() { AllowInsecureLoopback = true });
            var agent = new HeartbeatAuditAgent(f.First.Content.NodeId, f.First.Content.LedgerId, f.Cache,
                () => new MonitorHealth(MonitorState.Running, 1, 0, 0, 0, 1, 1, 0, null), auditTransport, f.Local.Node, f.Local.Server);
            auditResult = await agent.AuditOnceAsync();
            Assert.Equal(100, (await agent.RefreshHealthAsync()).Content.Assessment.Score);
            using var operatorClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { BaseAddress = address };
            Assert.Equal(dashboardEnabled ? System.Net.HttpStatusCode.Unauthorized : System.Net.HttpStatusCode.NotFound,
                (await operatorClient.GetAsync("/dashboard/api/fleet")).StatusCode);
            if (dashboardEnabled)
            {
                await DashboardTestHost.LoginAsync(operatorClient);
                string scope = DashboardTestHost.Scope(f.First.Content.NodeId, f.First.Content.LedgerId);
                using var dashboard = JsonDocument.Parse(await operatorClient.GetStringAsync("/dashboard/api/server?" + scope));
                Assert.Equal("Healthy", dashboard.RootElement.GetProperty("health").GetProperty("assessment").GetProperty("state").GetString());
                using var history = JsonDocument.Parse(await operatorClient.GetStringAsync("/dashboard/api/history?" + scope));
                Assert.Equal(1, history.RootElement.GetProperty("records").GetArrayLength());
            }
            else Assert.Equal(System.Net.HttpStatusCode.NotFound, (await operatorClient.GetAsync("/dashboard")).StatusCode);
            using var deliveryDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            bool committed = false;
            while (!committed)
            {
                using var notificationDb = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.Options.DatabasePath + ".notifications.db", Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
                notificationDb.Open(); using var query = notificationDb.CreateCommand(); query.CommandText = "SELECT COUNT(*) FROM deliveries WHERE state=2";
                committed = Convert.ToInt64(query.ExecuteScalar()) > 0;
                if (!committed) await Task.Delay(25, deliveryDeadline.Token);
            }
            Assert.True(webhook.Requests.Count >= 2);
        }
        finally
        {
            if (!child.HasExited) child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        }
        await TestLedger.AfterProcessExitAsync(()=>f.ReopenStoreAsync());
        var repeated = await f.Service.IngestAsync(f.First);
        Assert.Equal(receipt.Signature, repeated.Signature);
        Assert.Empty(await f.Cache.ReadPendingAsync());
        await using var auditStore = await SqliteHeartbeatAuditStore.OpenAsync(new() { DatabasePath = f.Options.DatabasePath + ".audits.db" }, f.Trust, f.Local.Server);
        var auditService = new HeartbeatAuditService(f.Trust, f.Store, auditStore, f.Local.Server, f.Local.Server);
        var latest = await auditStore.ReadLatestAsync(f.First.Content.NodeId, f.First.Content.LedgerId);
        Assert.Equal(auditResult.Signature, latest!.Result.Signature);
        Assert.Equal(ServerHealthState.Healthy, (await auditService.ReadNodeHealthAsync(f.First.Content.NodeId, f.First.Content.LedgerId)).Assessment.State);
        await using var notificationStore = await SqliteNotificationQueue.OpenAsync(new() { DatabasePath = f.Options.DatabasePath + ".notifications.db" });
        Assert.True((await notificationStore.CountAsync()).Delivered > 0);
    }
}
