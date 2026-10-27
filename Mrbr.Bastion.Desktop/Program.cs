namespace Mrbr.Bastion.Desktop;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => MessageBox.Show(e.Exception.Message, "Mrbr.Bastion", MessageBoxButtons.OK, MessageBoxIcon.Error);
        Application.Run(new MainForm(args.Length == 2 && args[0] == "--profile" ? args[1] : null));
    }
}
