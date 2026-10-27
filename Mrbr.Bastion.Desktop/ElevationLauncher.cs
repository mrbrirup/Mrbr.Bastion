using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Mrbr.Bastion.Desktop.Tests")]

namespace Mrbr.Bastion.Desktop;

internal static class ElevationLauncher
{
    internal static ProcessStartInfo CreateStartInfo(string executable, string assembly, string profile, nint owner)
    {
        var start = new ProcessStartInfo(Path.GetFullPath(executable))
        {
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(assembly))!,
            ErrorDialogParentHandle = owner,
            WindowStyle = ProcessWindowStyle.Normal
        };
        if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Path.GetFullPath(assembly));
        start.ArgumentList.Add("--profile");
        start.ArgumentList.Add(Path.GetFullPath(profile));
        return start;
    }

    internal static Task StartAsync(ProcessStartInfo start)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        // Shell execution can wait for Windows approval. Keep the form responsive and use an STA for Shell COM.
        var thread = new Thread(() =>
        {
            try
            {
                using var process = Process.Start(start) ?? throw new IOException("Windows did not return an elevated process.");
                completion.SetResult();
            }
            catch (Win32Exception error)
            {
                string explanation = error.NativeErrorCode == 1223
                    ? "Windows did not complete Administrator approval. The prompt may have been declined, timed out, or not displayed."
                    : "Windows could not start the elevated application: " + error.Message;
                completion.SetException(new InvalidOperationException($"{explanation} (Windows error {error.NativeErrorCode}.)\n\n" +
                    "This window remains open. You can launch the application from File Explorer using Run as administrator, " +
                    "then use File → Open to select the saved profile.\n\nApplication: " + start.FileName +
                    "\nProfile: " + start.ArgumentList[^1], error));
            }
            catch (Exception error) { completion.SetException(error); }
        }) { IsBackground = true, Name = "Bastion elevation handoff" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task;
    }
}
