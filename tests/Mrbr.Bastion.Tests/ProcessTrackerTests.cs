using Mrbr.Bastion.Core;
using Xunit;

namespace Mrbr.Bastion.Tests;

public sealed class ProcessTrackerTests
{
    [Fact]
    public void PidReuseCreatesANewLifetimeAndDoesNotAttributeOlderEventsToIt()
    {
        var tracker = new ProcessTracker();
        var start = DateTimeOffset.UtcNow;
        var first = tracker.Observe(42, 0, start, "first.exe", null, snapshot: false);
        tracker.Stop(42, start.AddSeconds(1));
        var second = tracker.Observe(42, 0, start.AddSeconds(2), "second.exe", null, snapshot: false);
        Assert.NotEqual(first.InstanceId, second.InstanceId);
        Assert.Null(tracker.Find(42, start.AddSeconds(1)));
        Assert.Null(tracker.Stop(42, start.AddSeconds(1)));
        Assert.Equal(second, tracker.Find(42, start.AddSeconds(3)));
    }

    [Fact]
    public void ParentCorrelationUsesKnownLifetimeAndRundownDoesNotReplaceAStart()
    {
        var tracker = new ProcessTracker();
        var now = DateTimeOffset.UtcNow;
        var parent = tracker.Observe(1, 0, now, "parent.exe", null, snapshot: true);
        var child = tracker.Observe(2, 1, now.AddSeconds(1), "child.exe", "arg", snapshot: false);
        Assert.Equal(parent.InstanceId, child.ParentInstanceId);
        Assert.Equal(child, tracker.Observe(2, 1, now.AddSeconds(2), null, null, snapshot: true));
    }

    [Fact]
    public void ExitedOrReusedParentDoesNotChangeTheChildsHistoricalContext()
    {
        var tracker = new ProcessTracker();
        var now = DateTimeOffset.UtcNow;
        var parent = tracker.Observe(10, 0, now, @"C:\php\php-cgi.exe", null, snapshot: false, "php-cgi");
        var child = tracker.Observe(20, 10, now.AddSeconds(1), "cmd.exe", null, snapshot: false);
        tracker.Stop(10, now.AddSeconds(2));
        var replacement = tracker.Observe(10, 0, now.AddSeconds(3), "unrelated.exe", null, snapshot: false);

        var retained = tracker.Find(20, now.AddSeconds(4))!;
        Assert.Equal(parent.InstanceId, retained.ParentProcess!.ProcessInstanceId);
        Assert.Equal("php-cgi", retained.ParentProcess.ProcessName);
        Assert.Equal(@"C:\php\php-cgi.exe", retained.ParentProcess.ExecutablePath);
        Assert.Equal(now, retained.ParentProcess.StartedUtc);
        Assert.NotEqual(replacement.InstanceId, retained.ParentInstanceId);
        Assert.Equal(child.ParentProcess, tracker.Stop(20, now.AddSeconds(5))!.ParentProcess);
    }

    [Fact]
    public void RundownPreservesReportedPidWithoutInventingTheParentsLifetime()
    {
        var tracker = new ProcessTracker();
        var now = DateTimeOffset.UtcNow;
        tracker.Observe(10, 0, now, "possibly-reused.exe", null, snapshot: true);
        var existingChild = tracker.Observe(20, 10, now.AddSeconds(1), "existing.exe", null, snapshot: true);
        Assert.Equal(10, existingChild.ParentProcessId);
        Assert.Null(existingChild.ParentInstanceId);
        Assert.Null(existingChild.ParentProcess);
        Assert.Null(existingChild.StartedUtc);

        // The same observed parent can be linked to a genuinely new child created after rundown.
        var newChild = tracker.Observe(21, 10, now.AddSeconds(2), "new.exe", null, snapshot: false);
        Assert.NotNull(newChild.ParentProcess);
        Assert.Null(newChild.ParentProcess.StartedUtc);
        Assert.Equal(now, newChild.ParentProcess.FirstObservedUtc);
    }

    [Fact]
    public void UnknownNewerOrSelfParentRemainsUncorrelated()
    {
        var tracker = new ProcessTracker();
        var now = DateTimeOffset.UtcNow;
        tracker.Observe(10, 0, now.AddSeconds(2), "newer.exe", null, snapshot: false);
        Assert.Null(tracker.Observe(20, 10, now, "child.exe", null, snapshot: false).ParentProcess);
        Assert.Null(tracker.Observe(21, 99, now, "child.exe", null, snapshot: false).ParentProcess);
        Assert.Null(tracker.Observe(10, 10, now.AddSeconds(3), "self.exe", null, snapshot: false).ParentProcess);
    }

    [Fact]
    public void DelayedStartAndStopDoNotReplaceOrRemoveANewerPidLifetime()
    {
        var tracker = new ProcessTracker();
        var now = DateTimeOffset.UtcNow;
        var current = tracker.Observe(10, 0, now.AddSeconds(2), "current.exe", null, snapshot: false);
        tracker.Observe(10, 0, now, "delayed.exe", null, snapshot: false);
        tracker.Observe(10, 0, now.AddSeconds(1), "old-snapshot.exe", null, snapshot: true);
        Assert.Null(tracker.Stop(10, now.AddSeconds(1)));
        var child = tracker.Observe(20, 10, now.AddSeconds(3), "child.exe", null, snapshot: false);
        Assert.Equal(current.InstanceId, child.ParentInstanceId);
        Assert.Equal("current.exe", child.ParentProcess!.ExecutablePath);
    }
}
