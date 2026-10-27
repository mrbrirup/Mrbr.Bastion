using System.ComponentModel;
using System.Runtime.Versioning;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Mrbr.Bastion.Abstraction;

namespace Mrbr.Bastion.Core;

/// <summary>
/// Privileged Windows kernel ETW collection. File events describe operations, not authorization or
/// successful completion. Rundown observations identify processes already running at session startup.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEtwTelemetrySource : IFilteredTelemetrySource
{
    private readonly WindowsEtwOptions _options;
    private readonly object _sessionGate = new();
    private readonly ProcessTracker _processes = new();
    private readonly FilteredFileEventDispatcher _files;
    private readonly EventIdSequence _eventIds = new(Guid.NewGuid());
    private RealtimeTraceLogFilter? _traceLog;
    private TraceEventSession? _session;
    private long _eventsLost;
    private int _started;

    public WindowsEtwTelemetrySource(WindowsEtwOptions? options = null)
    {
        _options = options ?? new WindowsEtwOptions();
        _files = new(pid => (!_options.ExcludeCollectorProcess || pid != Environment.ProcessId)
            && (_options.RetainFileIoProcess?.Invoke(pid) ?? true), (pid, path) => _traceLog?.Retain(pid, path) ?? true);
        if (_options.BufferSizeMegabytes is < 1 or > 1024)
            throw new ArgumentOutOfRangeException(nameof(options), "ETW buffer size must be between 1 and 1024 MB.");
    }

    public long FilteredEvents => _files.FilteredEvents;

    public long EventsLost
    {
        get
        {
            lock (_sessionGate)
            {
                CaptureLoss();
                return _eventsLost;
            }
        }
    }

    public Task RunAsync(Action<TelemetryEvent> onEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(onEvent);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Kernel ETW requires Windows.");
        if (Interlocked.Exchange(ref _started, 1) != 0) throw new InvalidOperationException("An ETW source can only run once.");
        cancellationToken.ThrowIfCancellationRequested();
        if (TraceEventSession.IsElevated() != true)
            throw new UnauthorizedAccessException("Kernel ETW collection requires an elevated Windows process. Run the host as Administrator.");
        return Task.Factory.StartNew(() => Collect(onEvent, cancellationToken), CancellationToken.None,
            TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    private void Collect(Action<TelemetryEvent> onEvent, CancellationToken cancellationToken)
    {
        var name = $"Mrbr.Bastion.{Environment.ProcessId}.{Guid.NewGuid():N}";
        _traceLog = new(Environment.GetFolderPath(Environment.SpecialFolder.Windows), name);
        using var session = new TraceEventSession(name, TraceEventSessionOptions.Create | TraceEventSessionOptions.NoRestartOnCreate)
        {
            BufferSizeMB = _options.BufferSizeMegabytes,
            StopOnDispose = true
        };
        // Source's getter starts the session. Kernel flags must be enabled before that first access,
        // otherwise TraceEvent rejects the already-started session even when its name is unique.
        var keywords = KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread;
        if (_options.CollectFileEvents)
            keywords |= KernelTraceEventParser.Keywords.FileIO | KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.DiskFileIO;
        session.EnableKernelProvider(keywords);
        using var source = session.Source;
        void Publish(TelemetryEvent item)
        {
            onEvent(item);
        }
        source.Kernel.ProcessStart += data => Publish(ProcessEvent(data, TelemetryEventKind.ProcessStarted));
        source.Kernel.ProcessStop += data => Publish(ProcessEvent(data, TelemetryEventKind.ProcessStopped));
        if (_options.IncludeExistingProcesses)
            source.Kernel.ProcessDCStart += data => Publish(ProcessEvent(data, TelemetryEventKind.ProcessSnapshot));
        if (_options.CollectFileEvents)
        {
            source.Kernel.FileIOCreate += _files.CreateCallback((FileIOCreateTraceData data) => data.ProcessID,
                data => FileEvent(data, TelemetryEventKind.FileOpened, data.FileName, data.FileObject), Publish, data => data.FileName);
            source.Kernel.FileIORead += _files.CreateCallback((FileIOReadWriteTraceData data) => data.ProcessID,
                data => FileEvent(data, TelemetryEventKind.FileRead, data.FileName, data.FileObject, data.IoSize), Publish, data => data.FileName);
            source.Kernel.FileIOWrite += _files.CreateCallback((FileIOReadWriteTraceData data) => data.ProcessID,
                data => FileEvent(data, TelemetryEventKind.FileWritten, data.FileName, data.FileObject, data.IoSize), Publish, data => data.FileName);
            source.Kernel.FileIOClose += _files.CreateCallback((FileIOSimpleOpTraceData data) => data.ProcessID,
                data => FileEvent(data, TelemetryEventKind.FileClosed, data.FileName, data.FileObject), Publish, data => data.FileName);
            source.Kernel.FileIODelete += _files.CreateCallback((FileIOInfoTraceData data) => data.ProcessID,
                data => FileEvent(data, TelemetryEventKind.FileDeleted, data.FileName, data.FileObject), Publish, data => data.FileName);
            source.Kernel.FileIORename += _files.CreateCallback((FileIOInfoTraceData data) => data.ProcessID,
                data => FileEvent(data, TelemetryEventKind.FileRenamed, data.FileName, data.FileObject), Publish, data => data.FileName);
            if (_options.CollectMetadataQueries)
                source.Kernel.FileIOQueryInfo += _files.CreateCallback((FileIOInfoTraceData data) => data.ProcessID,
                    data => FileEvent(data, TelemetryEventKind.FileMetadataQueried, data.FileName, data.FileObject), Publish, data => data.FileName);
        }

        lock (_sessionGate) _session = session;
        Exception? stopError = null;
        using var registration = cancellationToken.Register(() =>
        {
            lock (_sessionGate)
            {
                try
                {
                    CaptureLoss();
                    session.Dispose(); // Documented by TraceEvent as safe while Process runs on another thread.
                }
                catch (Exception error)
                {
                    stopError = error;
                    source.StopProcessing();
                }
                finally { _session = null; }
            }
        });
        try
        {
            source.Process();
            if (!cancellationToken.IsCancellationRequested)
                throw new IOException("The ETW session ended unexpectedly. Collection is no longer running.");
        }
        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested) { }
        finally
        {
            // Wait for any stop callback before reading its error and releasing the underlying handles.
            registration.Dispose();
            lock (_sessionGate)
            {
                CaptureLoss();
                _session = null;
            }
        }
        if (stopError is not null) throw new IOException("Stopping the ETW session failed.", stopError);
    }

    private void CaptureLoss()
    {
        if (_session is null) return;
        try { _eventsLost = Math.Max(_eventsLost, _session.EventsLost); }
        catch (Win32Exception) { /* An externally stopped session is reported by Collect, not as a healthy stop. */ }
    }

    private TelemetryEvent ProcessEvent(ProcessTraceData data, TelemetryEventKind kind)
    {
        var time = new DateTimeOffset(data.TimeStamp.ToUniversalTime());
        ProcessObservation? process;
        if (kind == TelemetryEventKind.ProcessStopped)
            process = _processes.Stop(data.ProcessID, time);
        else
            process = _processes.Observe(data.ProcessID, data.ParentID, time, NullIfEmpty(data.ImageFileName),
                NullIfEmpty(data.CommandLine), kind == TelemetryEventKind.ProcessSnapshot, NullIfEmpty(data.ProcessName));
        return new TelemetryEvent(_eventIds.Next())
        {
            TimestampUtc = time,
            Kind = kind,
            ProcessId = data.ProcessID,
            ProcessInstanceId = process?.InstanceId,
            ParentProcessId = process?.ParentProcessId ?? data.ParentID,
            ParentProcessInstanceId = process?.ParentInstanceId,
            ParentProcess = process?.ParentProcess,
            ProcessName = process?.ProcessName,
            ExecutablePath = NullIfEmpty(data.ImageFileName) ?? process?.ExecutablePath,
            CommandLine = NullIfEmpty(data.CommandLine) ?? process?.CommandLine
        };
    }

    private TelemetryEvent FileEvent(TraceEvent data, TelemetryEventKind kind, string? path, ulong fileObject, long? size = null)
    {
        var time = new DateTimeOffset(data.TimeStamp.ToUniversalTime());
        var process = _processes.Find(data.ProcessID, time);
        return new TelemetryEvent(_eventIds.Next())
        {
            TimestampUtc = time,
            Kind = kind,
            ProcessId = data.ProcessID,
            ProcessInstanceId = process?.InstanceId,
            ParentProcessId = process?.ParentProcessId,
            ParentProcessInstanceId = process?.ParentInstanceId,
            ParentProcess = process?.ParentProcess,
            ProcessName = process?.ProcessName,
            ExecutablePath = process?.ExecutablePath,
            CommandLine = process?.CommandLine,
            FilePath = NullIfEmpty(path),
            FileObject = fileObject,
            SizeBytes = size
        };
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
