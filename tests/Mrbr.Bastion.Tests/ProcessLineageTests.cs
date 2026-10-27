using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mrbr.Bastion.Abstraction;
using Mrbr.Bastion.Ingestion;
using Mrbr.Bastion.Inventory.Contracts;
using Mrbr.Bastion.Inventory.Sqlite;
using Mrbr.Bastion.Inventory.Windows;
using Mrbr.Bastion.Transport.Grpc;
using Mrbr.Bastion.Transport.Http;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class ProcessLineageTests
{
    private static ProcessParent Parent() => new(10, Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-1),
        ProcessName: "php-cgi", ExecutablePath: @"C:\php\php-cgi.exe");

    private static TelemetryEvent Child(ProcessParent parent) => TestLedger.Event(20) with
    {
        ProcessInstanceId = Guid.NewGuid(), ParentProcessId = parent.ProcessId,
        ParentProcessInstanceId = parent.ProcessInstanceId, ParentProcess = parent,
        ProcessName = "cmd", ExecutablePath = @"C:\Windows\System32\cmd.exe"
    };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignedParentContextSurvivesTransportSettlementAndCentralRestart(bool grpc)
    {
        await using var f = await IngestionFixture.CreateAsync();
        await f.Service.IngestAsync(f.First);
        var observation = Child(Parent());
        var block = await f.Cache.AppendAsync([observation]);
        await using (var host = await NetworkIngestionHost.StartAsync(f.Service))
        {
            if (grpc)
            {
                await using var transport = new GrpcTelemetryTransport(host.GrpcAddress, f.Local.Server, host.ClientOptions);
                await f.Cache.ReconcileAsync(await transport.SubmitAsync(block));
            }
            else
            {
                using var transport = new HttpTelemetryTransport(host.Address, f.Local.Server, host.ClientOptions);
                await f.Cache.ReconcileAsync(await transport.SubmitAsync(block));
            }
        }
        await f.ReopenStoreAsync();
        var stored = await f.Store.ReadAsync(block.Content.NodeId, block.Content.LedgerId, block.Content.SequenceNumber);
        Assert.NotNull(stored);
        Assert.Equal(observation, Assert.Single(LedgerProtocol.DeserializeEvents(stored.Block)));
        Assert.Equal(block.Content.Payload, stored.Block.Content.Payload);

        var changed = observation with { ParentProcess = observation.ParentProcess! with { ProcessName = "other" } };
        var tampered = block with { Content = block.Content with { Payload = LedgerProtocol.SerializeEvents([changed]) } };
        Assert.Equal(IngestionFailure.UntrustedBlock,
            (await Assert.ThrowsAsync<TelemetryRejectedException>(() => f.Service.IngestAsync(tampered))).Failure);
    }

    [Fact]
    public void ParentContextMustMatchTheSignedChildIdentitiesAndTimeline()
    {
        var parent = Parent();
        var child = Child(parent);
        var invalid = new[]
        {
            child with { ParentProcessId = 11 },
            child with { ParentProcessInstanceId = Guid.NewGuid() },
            child with { ProcessInstanceId = null },
            child with { ParentProcess = parent with { FirstObservedUtc = child.TimestampUtc.AddSeconds(1) } },
            child with { ParentProcess = parent with { StartedUtc = parent.FirstObservedUtc.AddSeconds(1) } },
            child with { ParentProcess = parent with { ProcessInstanceId = Guid.Empty } },
            child with { ParentProcess = parent with { ExecutablePath = new string('x', 32769) } },
            child with { ProcessId = parent.ProcessId },
            child with { ProcessInstanceId = parent.ProcessInstanceId }
        };
        foreach (var item in invalid)
            Assert.Throws<InvalidDataException>(() => LedgerProtocol.SerializeEvents([item]));
    }

    [Fact]
    public void AbsentLineageDoesNotChangeExistingPayloadEncoding()
    {
        var child = TestLedger.Event();
        var events = Encoding.UTF8.GetString(LedgerProtocol.SerializeEvents([child]));
        Assert.DoesNotContain("\"parentProcess\":", events);
        Assert.Null(JsonSerializer.Deserialize<TelemetryEvent[]>(events, new JsonSerializerOptions(JsonSerializerDefaults.Web))![0].ParentProcess);

        var row = SoftwareFixture.Record();
        var bytes = InventoryJson.Encode([row]);
        var oldPayload = JsonNode.Parse(bytes)!;
        Assert.False(oldPayload[0]!["artifact"]!.AsObject().ContainsKey("parentProcessId"));
        Assert.False(oldPayload[0]!["artifact"]!.AsObject().ContainsKey("parentProcess"));
        Assert.Equal(bytes, InventoryJson.Encode(InventoryJson.Decode(bytes)));
    }

    [Fact]
    public async Task StopEnrichmentRetainsParentContextWithoutLookingUpExitedProcesses()
    {
        var parent = Parent();
        var stopped = Child(parent) with { Kind = TelemetryEventKind.ProcessStopped, ProcessId = int.MaxValue };
        var source = new WindowsInventorySource(new UnexpectedInspector());
        var row = await source.EnrichProcessEventAsync(stopped);
        Assert.NotNull(row);
        InventoryJson.Validate(row);
        Assert.Equal(parent, row.Artifact!.ParentProcess);
        Assert.Equal(parent.ProcessId, row.Artifact.ParentProcessId);
        Assert.False(row.Artifact.ReportedRunning);
    }

    [Fact]
    public async Task InventoryRetainsParentContextOnExitAndAfterRestart()
    {
        await using var f = await SoftwareFixture.CreateAsync();
        var parent = Parent();
        var artifact = new SoftwareArtifact("cmd.exe", ProcessId: 20, ProcessInstanceId: Guid.NewGuid(),
            ReportedRunning: true, ParentProcessId: parent.ProcessId, ParentProcess: parent);
        var start = SoftwareFixture.Record(artifact: artifact, source: InventorySource.RunningProcess);
        await f.Inventory.ApplyAsync(await f.AppendAsync(start), DateTimeOffset.UtcNow);
        var stop = start with
        {
            Id = Guid.NewGuid(), Kind = InventoryRecordKind.ProcessStopped,
            Artifact = new("cmd.exe", ProcessId: 20, ProcessInstanceId: artifact.ProcessInstanceId)
        };
        await f.Inventory.ApplyAsync(await f.AppendAsync(stop), DateTimeOffset.UtcNow);
        await f.Inventory.DisposeAsync();
        await using var reopened = SqliteInventoryStore.Open(f.PathFor("inventory.db"));
        var retained = Assert.Single((await reopened.ReadAsync(f.Node, f.LedgerId)).Items).Observation.Artifact!;
        Assert.Equal(parent, retained.ParentProcess);
        Assert.Equal(parent.ProcessId, retained.ParentProcessId);
        Assert.False(retained.ReportedRunning);
    }

    [Fact]
    public void InventoryRejectsInconsistentOrNonProcessParentContext()
    {
        var parent = Parent();
        var artifact = new SoftwareArtifact("cmd.exe", ProcessId: 20, ProcessInstanceId: Guid.NewGuid(),
            ParentProcessId: 11, ParentProcess: parent);
        var row = SoftwareFixture.Record(artifact: artifact, source: InventorySource.RunningProcess);
        Assert.Throws<InvalidDataException>(() => InventoryJson.Encode([row]));
        Assert.Throws<InvalidDataException>(() => InventoryJson.Encode([row with
        {
            Source = InventorySource.FileSystem, Artifact = artifact with { ParentProcessId = parent.ProcessId }
        }]));
    }

    private sealed class UnexpectedInspector : IArtifactInspector
    {
        public Task<SoftwareArtifact> InspectAsync(string path, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Stopped-process enrichment must not inspect a current process or file.");
        public SoftwareArtifact InspectBytes(string location, string member, ReadOnlyMemory<byte> data) =>
            throw new InvalidOperationException("Unexpected inspection.");
    }
}
