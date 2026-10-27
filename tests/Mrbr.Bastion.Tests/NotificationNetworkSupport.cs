using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Mrbr.Bastion.Tests;

internal sealed record RecordedWebhook(byte[] Body, Dictionary<string, string> Headers);
internal sealed class NotificationWebhookHost(WebApplication app, Uri endpoint) : IAsyncDisposable
{
    public Uri Endpoint => endpoint;
    public ConcurrentQueue<RecordedWebhook> Requests { get; } = new();
    public int RedirectTargetRequests;
    public static async Task<NotificationWebhookHost> StartAsync(Func<int, HttpContext, Task<IResult>>? respond = null)
    {
        var builder = WebApplication.CreateSlimBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0));
        var app = builder.Build(); NotificationWebhookHost? host = null; int count = 0;
        app.MapPost("/hook", async (HttpContext context) =>
        {
            using var body = new MemoryStream(); await context.Request.Body.CopyToAsync(body, context.RequestAborted);
            host!.Requests.Enqueue(new(body.ToArray(), context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase)));
            int call = Interlocked.Increment(ref count); return respond is null ? Results.Ok() : await respond(call, context);
        });
        app.MapPost("/moved", () => { Interlocked.Increment(ref host!.RedirectTargetRequests); return Results.Ok(); });
        try
        {
            await app.StartAsync(); string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            host = new(app, new Uri(new Uri(address), "/hook")); return host;
        }
        catch { await app.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync() { await app.StopAsync(); await app.DisposeAsync(); }
}
internal sealed class NotificationSmtpHost : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentBag<Task> _connections = [];
    private readonly Func<int, int> _dataStatus;
    private readonly int _recipientStatus;
    private readonly bool _dropOnQuit;
    private Task _accept = Task.CompletedTask;
    private int _messages;
    public ConcurrentQueue<byte[]> Messages { get; } = new();
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public NotificationSmtpHost(Func<int, int>? dataStatus = null, int recipientStatus = 250, bool dropOnQuit = false)
    {
        _dataStatus = dataStatus ?? (_ => 250); _recipientStatus = recipientStatus; _dropOnQuit = dropOnQuit;
        _listener.Start(); _accept = AcceptAsync();
    }
    private async Task AcceptAsync()
    {
        try { while (!_stop.IsCancellationRequested) _connections.Add(HandleAsync(await _listener.AcceptTcpClientAsync(_stop.Token))); }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (SocketException) when (_stop.IsCancellationRequested) { }
    }
    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        try
        {
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, false, leaveOpen: true);
            using var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync("220 localhost test SMTP");
            while (await reader.ReadLineAsync(_stop.Token) is { } line)
            {
                if (line.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase) || line.StartsWith("HELO", StringComparison.OrdinalIgnoreCase)) await writer.WriteLineAsync("250 localhost");
                else if (line.StartsWith("MAIL FROM:", StringComparison.OrdinalIgnoreCase)) await writer.WriteLineAsync("250 sender accepted");
                else if (line.StartsWith("RCPT TO:", StringComparison.OrdinalIgnoreCase)) await writer.WriteLineAsync(_recipientStatus + " recipient response");
                else if (line == "DATA")
                {
                    await writer.WriteLineAsync("354 send message"); var data = new StringBuilder();
                    while (await reader.ReadLineAsync(_stop.Token) is { } item && item != ".") data.AppendLine(item.StartsWith("..", StringComparison.Ordinal) ? item[1..] : item);
                    Messages.Enqueue(Encoding.ASCII.GetBytes(data.ToString())); int status = _dataStatus(Interlocked.Increment(ref _messages));
                    if (status == 0) return; // Simulate acceptance followed by a lost SMTP acknowledgement.
                    await writer.WriteLineAsync(status + " DATA response");
                }
                else if (line == "QUIT") { if (!_dropOnQuit) await writer.WriteLineAsync("221 goodbye"); return; }
                else if (line is "RSET" or "NOOP") await writer.WriteLineAsync("250 OK");
                else await writer.WriteLineAsync("500 unsupported command");
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (IOException) { }
    }
    public async ValueTask DisposeAsync()
    {
        _stop.Cancel(); _listener.Stop(); await _accept; await Task.WhenAll(_connections.ToArray()); _stop.Dispose();
    }
}
