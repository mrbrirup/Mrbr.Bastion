using System.ComponentModel;
using System.ComponentModel.Design;
using System.Runtime.ExceptionServices;
using Mrbr.Bastion.Configuration;
using Mrbr.Bastion.Notifications.Smtp;
using Xunit;

namespace Mrbr.Bastion.Desktop.Tests;

public sealed class PropertySheetTests
{
    [Fact]
    public void RetentionPolicyIsEditableThroughTheNestedPropertyGrid() => Sta(() =>
    {
        var profile=new LauncherProfile();using var root=new PropertySheet(profile.Collector,"Collector",profile.DeploymentDirectory);
        var policy=Assert.IsType<PropertySheet>(TypeDescriptor.GetProperties(root)["Retention"]!.GetValue(root));
        var properties=TypeDescriptor.GetProperties(policy);properties["Enabled"]!.SetValue(policy,true);properties["KeepRecentBlocks"]!.SetValue(policy,64);
        properties["ArchiveDirectory"]!.SetValue(policy,"archives");
        Assert.True(profile.Collector.Retention.Enabled);Assert.Equal(64,profile.Collector.Retention.KeepRecentBlocks);Assert.Equal("archives",profile.Collector.Retention.ArchiveDirectory);
        Assert.Contains("unsettled",properties["Enabled"]!.Description,StringComparison.OrdinalIgnoreCase);
    });

    [Theory]
    [InlineData("Mrbr.Bastion.Desktop.exe", false)]
    [InlineData("dotnet.exe", true)]
    public void ElevationHandoffPreservesProfileAndOwnerWindow(string executableName, bool frameworkHost)
    {
        string root = Path.Combine(Path.GetTempPath(), "Bastion launch with spaces");
        string assembly = Path.Combine(root, "Mrbr.Bastion.Desktop.dll");
        string profile = Path.Combine(root, "saved profile.json");
        var start = ElevationLauncher.CreateStartInfo(Path.Combine(root, executableName), assembly, profile, new nint(123));
        Assert.True(start.UseShellExecute);
        Assert.Equal("runas", start.Verb);
        Assert.Equal(new nint(123), start.ErrorDialogParentHandle);
        Assert.Equal(root, start.WorkingDirectory);
        Assert.Equal(frameworkHost ? new[] { assembly, "--profile", profile } : new[] { "--profile", profile }, start.ArgumentList);
    }

    [Fact]
    public void OpeningAProfileDisplaysItsLoadedValuesImmediately() => Sta(() =>
    {
        string root = Path.Combine(Path.GetTempPath(), "Mrbr.Bastion.Desktop.Tests", Guid.NewGuid().ToString("N"));
        try
        {
            var profile = new LauncherProfile { DeploymentDirectory = Path.Combine(root, "deployment") };
            string path = Path.Combine(root, "desktop.bastion.local.json");
            ProfileStorage.Save(path, profile);
            using var form = new MainForm(path);
            form.Show(); Application.DoEvents();
            static IEnumerable<Control> Descendants(Control parent) => parent.Controls.Cast<Control>()
                .SelectMany(child => new[] { child }.Concat(Descendants(child)));
            var grid = Assert.Single(Descendants(form).OfType<PropertyGrid>());
            var loaded = Assert.IsType<LauncherProfile>(Assert.IsType<PropertySheet>(grid.SelectedObject).Value);
            Assert.Equal(profile.DeploymentDirectory, loaded.DeploymentDirectory);
            Assert.Equal(profile.DeploymentDirectory, TypeDescriptor.GetProperties(grid.SelectedObject!)["DeploymentDirectory"]!.GetValue(grid.SelectedObject));
            form.Close(); Application.DoEvents();
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    });

    [Fact]
    public void PropertyGridEditsRealNestedObjectsAndMasksSessionSecrets() => Sta(() =>
    {
        var profile = new LauncherProfile();
        using var root = new PropertySheet(profile, "Profile", profile.DeploymentDirectory);
        using var grid = new PropertyGrid { SelectedObject = root, CommandsVisibleIfAvailable = true };
        var receiver = (PropertySheet)TypeDescriptor.GetProperties(root)["Receiver"]!.GetValue(root)!;
        var bastion = (PropertySheet)TypeDescriptor.GetProperties(receiver)["Bastion"]!.GetValue(receiver)!;
        TypeDescriptor.GetProperties(bastion)["DatabasePath"]!.SetValue(bastion, "data/changed.db");
        Assert.Equal("data/changed.db", profile.Receiver.Bastion.DatabasePath);
        Assert.False(string.IsNullOrEmpty(TypeDescriptor.GetProperties(bastion)["DatabasePath"]!.Description));
        var route = new SmtpNotificationOptions { RouteId = "mail", Host = "example.test", From = "a@example.test", To = "b@example.test" };
        using var sheet = new PropertySheet(route, "Email", profile.DeploymentDirectory);
        var password = TypeDescriptor.GetProperties(sheet)["Password"]!;
        Assert.True(((PasswordPropertyTextAttribute)password.Attributes[typeof(PasswordPropertyTextAttribute)]!).Password);
        Assert.False(password.IsReadOnly); password.SetValue(sheet, "session-only-fixture");
        Assert.Equal("session-only-fixture", route.Password);
    });

    [Fact]
    public void PropertyGridObjectsExposeInvokableDesignerVerbs() => Sta(() =>
    {
        bool invoked = false;
        using var sheet = new PropertySheet(new RequiredKeys(), "Keys", Path.GetTempPath(),
            [new DesignerVerb("Create keys", (_, _) => invoked = true)]);
        var commands = (IMenuCommandService)sheet.Site!.GetService(typeof(IMenuCommandService))!;
        Assert.Single(commands.Verbs.Cast<DesignerVerb>()); commands.Verbs[0]!.Invoke(); Assert.True(invoked);
        using var form = new MainForm(); form.CreateControl();
        Assert.Contains("Mrbr.Bastion", form.Text);
    });

    private static void Sta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() => { try { action(); } catch (Exception caught) { error = caught; } });
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); thread.Join();
        if (error is not null) ExceptionDispatchInfo.Capture(error).Throw();
    }
}
