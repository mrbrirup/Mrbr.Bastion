using System.ComponentModel.Design;
using System.Diagnostics;
using System.Security.Principal;
using Mrbr.Bastion.Configuration;

namespace Mrbr.Bastion.Desktop;

public sealed class MainForm : Form
{
    private LauncherProfile _profile = new();
    private string? _profileFile;
    private bool _dirty, _busy, _allowClose;
    private CancellationTokenSource? _selectedRunStop;
    private readonly ManagedProcesses _processes = new();
    private readonly PropertyGrid _properties = new() { Dock = DockStyle.Fill, HelpVisible = true, CommandsVisibleIfAvailable = true,
        PropertySort = PropertySort.Categorized, AccessibleName = "Configuration properties" };
    private readonly TreeView _sections = new() { Dock = DockStyle.Fill, HideSelection = false, ShowLines = false, ShowRootLines = false,
        AccessibleName = "Configuration sections", ItemHeight = 30 };
    private readonly TextBox _log = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both,
        WordWrap = false, Font = new("Consolas", 9), AccessibleName = "Process and command log" };
    private readonly ListView _status = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, AccessibleName = "Managed processes" };
    private readonly ToolStripStatusLabel _footer = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly Label _context = new() { Dock = DockStyle.Top, Height = 62, Padding = new(12), AutoEllipsis = true };
    private readonly Dictionary<string, Command> _commands = [];
    private sealed record Command(string Title, Func<Task> Action, bool RequiresStopped = false);

    public MainForm(string? profileFile = null)
    {
        Text = "Mrbr.Bastion · Configuration and run control";
        StartPosition = FormStartPosition.CenterScreen; Size = new(1280, 900); MinimumSize = new(1000, 720);
        AutoScaleMode = AutoScaleMode.Dpi; Font = new("Segoe UI", 9F);
        BuildCommands();
        var menu = new MenuStrip();
        AddMenu(menu, "File", "New", "Open", "Save", "Save as", "Export", "Open folder", "Save screenshot");
        AddMenu(menu, "Setup", "Validate", "Create keys", "Verify keys", "Apply key paths", "Initialize and enroll", "Create administrator", "Check HTTPS certificate", "Trust development certificate");
        AddMenu(menu, "Run", "Start selected", "Start receiver", "Start collector", "Start inventory", "Stop all", "Force stop", "Open dashboard");
        AddMenu(menu, "Storage", "Verify cache history", "Archive settled caches", "Compact caches");
        AddMenu(menu, "Help", "Help", "Restart elevated"); MainMenuStrip = menu;
        var toolbar = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Padding = new(6) };
        foreach (string name in new[] { "Save", "Validate", "Create keys", "Initialize and enroll", "Start selected", "Stop all", "Open dashboard" })
        { var button = new ToolStripButton(name) { ToolTipText = _commands[name].Title }; button.Click += async (_, _) => await ExecuteAsync(_commands[name]); toolbar.Items.Add(button); }
        var heading = new Panel { Dock = DockStyle.Top, Height = 76, BackColor = Color.FromArgb(27, 45, 65) };
        heading.Controls.Add(new Label { Text = "MRBR.BASTION   /   Desktop control panel", ForeColor = Color.White,
            Font = new(Font, FontStyle.Bold), Dock = DockStyle.Top, Height = 36, Padding = new(14, 12, 0, 0) });
        heading.Controls.Add(new Label { Text = "Configure → create keys → enroll → bootstrap → validate → run", ForeColor = Color.Gainsboro,
            Dock = DockStyle.Bottom, Height = 32, Padding = new(14, 0, 0, 0) });
        var mainSplit = new SplitContainer { Size = new(1250, 520), Dock = DockStyle.Fill, SplitterDistance = 250, FixedPanel = FixedPanel.Panel1 };
        foreach (string section in new[] { "Workspace", "Receiver", "Telemetry collector", "Software inventory", "Signing keys", "Runtime binaries" }) _sections.Nodes.Add(section);
        mainSplit.Panel1.Controls.Add(_sections);
        mainSplit.Panel2.Controls.Add(_properties); mainSplit.Panel2.Controls.Add(_context);
        var bottom = new SplitContainer { Size = new(1250, 180), Dock = DockStyle.Fill, SplitterDistance = 340, FixedPanel = FixedPanel.Panel1 };
        _status.Columns.Add("Component", 120); _status.Columns.Add("State", 190);
        bottom.Panel1.Controls.Add(_status); bottom.Panel2.Controls.Add(_log);
        var vertical = new SplitContainer { Size = new(1250, 720), Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 520,
            Panel1MinSize = 280, Panel2MinSize = 120 };
        vertical.Panel1.Controls.Add(mainSplit); vertical.Panel2.Controls.Add(bottom);
        var footer = new StatusStrip(); footer.Items.Add(_footer);
        Controls.Add(vertical); Controls.Add(footer); Controls.Add(heading); Controls.Add(toolbar); Controls.Add(menu);
        _sections.AfterSelect += (_, _) => SelectSection();
        _properties.PropertyValueChanged += (_, _) => { _dirty = true; UpdateState(); };
        _properties.HelpRequested += (_, _) => ShowHelp();
        HelpRequested += (_, _) => ShowHelp();
        _processes.Output += Log;
        _processes.Changed += () => Ui(UpdateState);
        FormClosing += ClosingAsync;
        FormClosed += (_, _) => CancelSelectedRun();
        Shown += (_, _) =>
        {
            if (profileFile is not null)
                try { _profile = ProfileStorage.Load(profileFile); _profileFile = Path.GetFullPath(profileFile); }
                catch (Exception error) { MessageBox.Show(this, error.Message, "Profile could not be opened", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            _sections.SelectedNode = _sections.Nodes[0]; SelectSection();
            Log("Ready. Open Help for the setup sequence. Secrets are session-only; existing keys and ledgers are preserved.");
        };
    }
    private void BuildCommands()
    {
        void Add(string name, Func<Task> action, bool stopped = false) => _commands.Add(name, new(name, action, stopped));
        Task Done(Action action) { action(); return Task.CompletedTask; }
        Add("New", () => Done(() => { if (!ConfirmDiscard()) return; _profile = new(); _profileFile = null; _dirty = false; SelectSection(); }), true);
        foreach (var (title, operation) in new[] { ("Verify cache history", "verify"), ("Archive settled caches", "retain"), ("Compact caches", "compact") })
            Add(title, async () =>
            {
                if (operation == "retain" && !SaveProfile(false)) return;
                foreach (string result in await Task.Run(() => ConfigurationActions.MaintainCachesAsync(_profile, operation))) Log(result);
            }, true);
        Add("Open", () => Done(() =>
        {
            if (!ConfirmDiscard()) return;
            using var dialog = new OpenFileDialog { Filter = "Bastion profile (*.json)|*.json", Title = "Open desktop profile" };
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            var loaded = ProfileStorage.Load(dialog.FileName); _profile = loaded; _profileFile = dialog.FileName; _dirty = false; SelectSection();
        }), true);
        Add("Save", () => Done(() => SaveProfile(false)));
        Add("Save as", () => Done(() => SaveProfile(true)));
        Add("Export", () => Done(() => { ConfigurationActions.Validate(_profile, false); ProfileStorage.Export(_profile); Log("Exported server.json, inventory.json and collector-retention.local.json without secret values to " + _profile.DeploymentDirectory); }), true);
        Add("Open folder", () => Done(() => { Directory.CreateDirectory(_profile.DeploymentDirectory); Process.Start(new ProcessStartInfo(_profile.DeploymentDirectory) { UseShellExecute = true }); }));
        Add("Save screenshot", () => Done(SaveScreenshot));
        Add("Validate", () => Done(() => { ConfigurationActions.Validate(_profile, true); Log("Selected configuration and binaries validated. HTTPS trust and remote connectivity are checked by the runtime; ensure ledgers are enrolled."); }), true);
        Add("Create keys", () => Done(() =>
        {
            foreach (var pair in new[] { _profile.Keys.Receiver, _profile.Keys.Node })
            {
                bool exists = File.Exists(_profile.Resolve(pair.PrivateKeyPath)) || File.Exists(_profile.Resolve(pair.PublicKeyPath));
                string id = exists ? PemKeyService.VerifyPair(_profile, pair) : PemKeyService.CreatePair(_profile, pair);
                Log((exists ? "Verified" : "Created") + " signing pair. Public fingerprint: " + id);
            }
            PemKeyService.ApplyPaths(_profile); _dirty = true; _properties.Refresh();
        }), true);
        Add("Verify keys", () => Done(() => { foreach (var pair in new[] { _profile.Keys.Receiver, _profile.Keys.Node }) Log("Verified P-256 pair: " + PemKeyService.VerifyPair(_profile, pair)); }), true);
        Add("Apply key paths", () => Done(() => { PemKeyService.ApplyPaths(_profile); _dirty = true; _properties.Refresh(); Log("Applied signing pair paths to receiver and agents. Enrollment retains its explicit public key paths."); }), true);
        Add("Initialize and enroll", async () =>
        {
            foreach (var checkpoint in await ConfigurationActions.InitializeLedgersAsync(_profile)) Log($"Enrolled {checkpoint.NodeId}, ledger {checkpoint.LedgerId:D}, sequence {checkpoint.SequenceNumber}.");
            _dirty = true; _properties.Refresh(); Log("Enrollment changed in this profile. Save and export before starting, or provision the enrollment on the remote receiver.");
        }, true);
        Add("Create administrator", async () =>
        {
            using var dialog = new AdministratorDialog();
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            try { await ConfigurationActions.BootstrapAdministratorAsync(_profile, dialog.UserName, dialog.Password); Log("Initial administrator created. Sign in through the dashboard; password was not saved or logged."); }
            finally { dialog.ClearPassword(); }
        }, true);
        Add("Check HTTPS certificate", () => CertificateAsync(false), true);
        Add("Trust development certificate", async () =>
        {
            if (MessageBox.Show(this, "Create/trust an ASP.NET Core development HTTPS certificate for this Windows user? This is for local development. Windows may ask you to approve certificate trust.", "Development HTTPS", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK)
                await CertificateAsync(true);
        }, true);
        Add("Start selected", async () =>
        {
            var targets = new[] { RunTarget.Receiver, RunTarget.Inventory, RunTarget.Collector }.Where(t => ConfigurationActions.Selected(_profile, t)).ToArray();
            if (targets.Length == 0) throw new InvalidOperationException("Select at least one component in Workspace.");
            Preflight(targets); ProfileStorage.Export(_profile);
            foreach (var target in targets) await _processes.StartAsync(target, RunPlan.Create(_profile, target));
            ArmSelectedRun();
        }, true);
        foreach (RunTarget target in Enum.GetValues<RunTarget>())
            Add("Start " + target.ToString().ToLowerInvariant(), async () => { Preflight([target]); if (!_processes.AnyRunning) ProfileStorage.Export(_profile); await _processes.StartAsync(target, RunPlan.Create(_profile, target)); });
        Add("Stop all", () => { CancelSelectedRun(); return _processes.StopAllAsync(); });
        Add("Force stop", () => Done(() =>
        {
            if (!_processes.AnyRunning) return;
            if (MessageBox.Show(this, "Force termination can lose accepted but uncommitted events. Terminate all processes started by this control panel?", "Force stop", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) == DialogResult.OK)
            { CancelSelectedRun(); foreach (RunTarget target in Enum.GetValues<RunTarget>()) _processes.ForceStop(target); }
        }));
        Add("Open dashboard", () => Done(() =>
        {
            var address = new Uri(_profile.Receiver.Kestrel.Endpoints.Https.Url);
            if (address.Scheme != "https") throw new InvalidOperationException("Use a configured HTTPS receiver endpoint.");
            var url = new UriBuilder(address) { Path = "/dashboard" };
            if (url.Host is "0.0.0.0" or "::") url.Host = "localhost";
            Process.Start(new ProcessStartInfo(url.Uri.AbsoluteUri) { UseShellExecute = true });
        }));
        Add("Help", () => Done(ShowHelp));
        Add("Restart elevated", async () =>
        {
            if (Elevated()) { Log("This control panel is already running as Administrator."); return; }
            if (!SaveProfile(false)) return;
            Activate();
            var start = ElevationLauncher.CreateStartInfo(Environment.ProcessPath!, typeof(MainForm).Assembly.Location, _profileFile!, Handle);
            Log("Requesting Windows Administrator approval for " + start.FileName + ". Approve the Windows prompt yourself; this window remains open until Windows starts the replacement.");
            await ElevationLauncher.StartAsync(start);
            _allowClose = true; Close();
        }, true);
    }
    private void Preflight(RunTarget[] targets)
    {
        if ((targets.Contains(RunTarget.Collector) && !_profile.Collector.SendOnly || targets.Contains(RunTarget.Inventory) && _profile.Inventory.ProcessEvents) && !Elevated())
            throw new InvalidOperationException("Live ETW requires Administrator privileges. Use Help → Restart elevated, or run Visual Studio as Administrator.");
        ConfigurationActions.Validate(_profile, true);
        foreach (var target in targets)
        {
            _ = RunPlan.Create(_profile, target);
            if (target == RunTarget.Collector && !File.Exists(_profile.Resolve(_profile.Collector.CacheDatabasePath))
                || target == RunTarget.Inventory && !File.Exists(_profile.Resolve(_profile.Inventory.CacheDatabasePath)))
                throw new InvalidOperationException("Initialize and enroll ledgers before starting agents.");
        }
    }
    private void CancelSelectedRun() { _selectedRunStop?.Cancel(); _selectedRunStop = null; }
    private void ArmSelectedRun()
    {
        CancelSelectedRun();
        if (_profile.SelectedRunDurationSeconds == 0) return;
        var stop = new CancellationTokenSource(); _selectedRunStop = stop;
        Log($"Bounded run: graceful Stop all after {_profile.SelectedRunDurationSeconds} seconds. Midpoint/final screenshots and the command log will be saved locally.");
        _ = FinishSelectedRunAsync(_profile.SelectedRunDurationSeconds, stop);
    }
    private async Task FinishSelectedRunAsync(int seconds, CancellationTokenSource stop)
    {
        void Snapshot()
        {
            try { SaveScreenshot(); }
            catch (Exception error) { Log("Run screenshot failed: " + error.Message); }
        }
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(seconds / 2d), stop.Token);
            if (!_busy && _processes.AnyRunning) Snapshot();
            await Task.Delay(TimeSpan.FromSeconds(seconds / 2d), stop.Token);
            while (_busy) await Task.Delay(100, stop.Token);
            stop.Token.ThrowIfCancellationRequested();
            await ExecuteAsync(new("Timed Stop all", async () =>
            {
                Log("Bounded run reached its deadline; stopping all managed components gracefully.");
                await _processes.StopAllAsync(); Snapshot();
                string folder = _profile.Resolve("logs"); Directory.CreateDirectory(folder);
                string path = Path.Combine(folder, $"selected-run-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.log");
                File.WriteAllText(path, _log.Text); Log("Saved bounded run log: " + path);
            }));
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (Exception error) { Log("Bounded run failed: " + error.Message); }
        finally { if (ReferenceEquals(_selectedRunStop, stop)) _selectedRunStop = null; stop.Dispose(); }
    }
    private void AddMenu(MenuStrip menu, string title, params string[] commands)
    {
        var root = new ToolStripMenuItem(title);
        foreach (string name in commands)
        {
            var item = new ToolStripMenuItem(name);
            item.ShortcutKeys = name switch
            {
                "Save" => Keys.Control | Keys.S, "Open" => Keys.Control | Keys.O,
                "Export" => Keys.Control | Keys.E, "Validate" => Keys.Control | Keys.L,
                "Create keys" => Keys.Control | Keys.Shift | Keys.K,
                "Initialize and enroll" => Keys.Control | Keys.Shift | Keys.I,
                "Start selected" => Keys.Control | Keys.Shift | Keys.F6,
                "Verify cache history" => Keys.Control | Keys.Shift | Keys.V,
                "Archive settled caches" => Keys.Control | Keys.Shift | Keys.A,
                "Compact caches" => Keys.Control | Keys.Shift | Keys.C,
                "Save screenshot" => Keys.Control | Keys.Shift | Keys.F12,
                "Stop all" => Keys.Control | Keys.Shift | Keys.F5, _ => Keys.None
            };
            item.Click += async (_, _) => await ExecuteAsync(_commands[name]); root.DropDownItems.Add(item);
        }
        menu.Items.Add(root);
    }
    private async Task ExecuteAsync(Command command)
    {
        if (_busy) return;
        try
        {
            if (command.RequiresStopped && _processes.AnyRunning) throw new InvalidOperationException("Stop managed processes before this operation.");
            _busy = true; UpdateState(); await command.Action();
        }
        catch (Exception error) { Log(command.Title + ": " + error.Message); MessageBox.Show(this, error.Message, command.Title, MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { _busy = false; UpdateState(); }
    }
    private void SelectSection()
    {
        string selected = _sections.SelectedNode?.Text ?? "Workspace";
        object value = selected switch { "Receiver" => _profile.Receiver, "Telemetry collector" => _profile.Collector,
            "Software inventory" => _profile.Inventory, "Signing keys" => _profile.Keys, "Runtime binaries" => _profile.Runtime, _ => _profile };
        string[] names = selected switch
        {
            "Signing keys" => ["Create keys", "Verify keys", "Apply key paths"],
            "Receiver" => ["Create administrator", "Start receiver", "Open dashboard"],
            "Telemetry collector" => ["Initialize and enroll", "Start collector", "Stop all", "Verify cache history", "Archive settled caches", "Compact caches"],
            "Software inventory" => ["Initialize and enroll", "Start inventory", "Stop all", "Verify cache history", "Archive settled caches", "Compact caches"],
            _ => ["Validate", "Export", "Start selected", "Stop all"]
        };
        _properties.SelectedObject = new PropertySheet(value, selected, _profile.DeploymentDirectory,
            names.Select(name => new DesignerVerb(name, async (_, _) => await ExecuteAsync(_commands[name]))));
        _context.Text = selected + "  ·  Edit properties below. Use […] for collections/files, description pane for help, and command links for actions.";
        UpdateState();
    }
    private bool SaveProfile(bool chooseFile)
    {
        if (_profileFile is null && !chooseFile)
        {
            string defaultFile = _profile.Resolve("desktop.bastion.local.json");
            if (!File.Exists(defaultFile)) _profileFile = defaultFile;
        }
        if (_profileFile is null || chooseFile)
        {
            using var dialog = new SaveFileDialog { Filter = "Bastion desktop profile (*.json)|*.json", FileName = "desktop.bastion.local.json", Title = "Save profile without secret values" };
            if (dialog.ShowDialog(this) != DialogResult.OK) return false;
            _profileFile = dialog.FileName;
        }
        ProfileStorage.Save(_profileFile, _profile); _dirty = false; Log("Saved profile without secret values: " + _profileFile); return true;
    }
    private bool ConfirmDiscard()
    {
        if (!_dirty) return true;
        return MessageBox.Show(this, "Save your profile changes first?", "Unsaved configuration", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) switch
        { DialogResult.Yes => SaveProfile(false), DialogResult.No => true, _ => false };
    }
    private async void ClosingAsync(object? sender, FormClosingEventArgs e)
    {
        if (_allowClose) return;
        e.Cancel = true;
        if (_busy || !ConfirmDiscard()) return;
        if (_processes.AnyRunning)
        {
            if (MessageBox.Show(this, "Gracefully stop the processes started by this control panel before closing?", "Managed processes are running", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            await ExecuteAsync(new("Stop before closing", () => _processes.StopAllAsync()));
            if (_processes.AnyRunning) return;
        }
        _allowClose = true; Close();
    }
    private async Task CertificateAsync(bool trust)
    {
        var info = new ProcessStartInfo(_profile.Runtime.DotnetExecutable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in new[] { "dev-certs", "https", trust ? "--trust" : "--check" }) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new IOException("Could not start dotnet dev-certs.");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync(); Log((await output) + (await error));
        if (process.ExitCode != 0) throw new InvalidOperationException("Certificate command failed. See the command log.");
    }
    private void ShowHelp()
    {
        using var form = new Form { Text = "Mrbr.Bastion · Configuration help", Size = new(800, 760), StartPosition = FormStartPosition.CenterParent };
        string context = _properties.SelectedGridItem?.PropertyDescriptor?.Description ?? "";
        form.Controls.Add(new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, Text = context + "\n\n" + HelpText.Overview, Font = Font, BackColor = SystemColors.Window });
        form.ShowDialog(this);
    }
    private void SaveScreenshot()
    {
        if (WindowState == FormWindowState.Minimized)
            throw new InvalidOperationException("Restore the configuration window before saving a screenshot. A minimized window only renders its title bar.");
        string section = string.Concat((_sections.SelectedNode?.Text ?? "Workspace").Where(char.IsAsciiLetterOrDigit));
        string folder = _profile.Resolve("screenshots"); Directory.CreateDirectory(folder);
        string destination = Path.Combine(folder, $"{section}-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.png");
        // Render only this application. No other desktop windows, private keys or password dialogs are captured.
        bool wasBusy = _busy;
        _busy = false; UpdateState();
        try
        {
            Refresh();
            using var bitmap = new Bitmap(Width, Height);
            DrawToBitmap(bitmap, new Rectangle(Point.Empty, Size));
            bitmap.Save(destination, System.Drawing.Imaging.ImageFormat.Png);
            Log("Saved application view: " + destination);
        }
        finally { _busy = wasBusy; }
    }
    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        if ((keyData & Keys.Modifiers) == Keys.Control)
        {
            int index = (int)(keyData & Keys.KeyCode) - (int)Keys.D1;
            if (index >= 0 && index < _sections.Nodes.Count)
            { _sections.SelectedNode = _sections.Nodes[index]; _properties.Focus(); return true; }
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }
    private static bool Elevated() => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    private void Ui(Action action) { if (!IsDisposed && IsHandleCreated) { if (InvokeRequired) BeginInvoke(action); else action(); } }
    private void Log(string text) => Ui(() => { if (_log.TextLength > 180000) _log.Text = _log.Text[^90000..]; _log.AppendText($"{DateTime.Now:HH:mm:ss}  {text.TrimEnd()}\r\n"); });
    private void UpdateState()
    {
        _properties.Enabled = !_busy && !_processes.AnyRunning;
        _status.Items.Clear(); foreach (RunTarget target in Enum.GetValues<RunTarget>()) _status.Items.Add(new ListViewItem([target.ToString(), _processes.Status(target)]));
        _footer.Text = (_busy ? "Working…   " : "") + (Elevated() ? "Administrator" : "Standard user · elevate for live ETW") + "   |   " + (_profileFile ?? "Unsaved profile") + (_dirty ? " *" : "");
        Text = "Mrbr.Bastion · Configuration and run control" + (_dirty ? " *" : "");
    }
}
