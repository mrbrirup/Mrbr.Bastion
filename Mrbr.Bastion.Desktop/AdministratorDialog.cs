namespace Mrbr.Bastion.Desktop;

internal sealed class AdministratorDialog : Form
{
    private readonly TextBox _name = new() { Dock = DockStyle.Fill, MaxLength = 64 };
    private readonly TextBox _password = new() { Dock = DockStyle.Fill, UseSystemPasswordChar = true, MaxLength = 128 };
    private readonly TextBox _confirm = new() { Dock = DockStyle.Fill, UseSystemPasswordChar = true, MaxLength = 128 };
    public string UserName => _name.Text;
    public string Password => _password.Text;
    public void ClearPassword() { _password.Clear(); _confirm.Clear(); }
    public AdministratorDialog()
    {
        Text = "Create first administrator"; StartPosition = FormStartPosition.CenterParent;
        ClientSize = new(530, 260); FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new(16), ColumnCount = 2, RowCount = 5 };
        layout.ColumnStyles.Add(new(SizeType.Absolute, 150)); layout.ColumnStyles.Add(new(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = "Username", AutoSize = true }, 0, 0); layout.Controls.Add(_name, 1, 0);
        layout.Controls.Add(new Label { Text = "Password (15–128)", AutoSize = true }, 0, 1); layout.Controls.Add(_password, 1, 1);
        layout.Controls.Add(new Label { Text = "Confirm password", AutoSize = true }, 0, 2); layout.Controls.Add(_confirm, 1, 2);
        var note = new Label { Text = "The receiver must be stopped. Bootstrap works only on an empty operator store. Passwords are not saved in the desktop profile.", AutoSize = true, MaximumSize = new(490, 0) };
        layout.Controls.Add(note, 0, 3); layout.SetColumnSpan(note, 2);
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        var create = new Button { Text = "Create", AutoSize = true };
        create.Click += (_, _) => { if (_password.Text != _confirm.Text || _password.Text.Length < 15) { MessageBox.Show(this, "Enter matching passwords of 15–128 characters."); return; } DialogResult = DialogResult.OK; };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        buttons.Controls.Add(create); buttons.Controls.Add(cancel); layout.Controls.Add(buttons, 1, 4);
        Controls.Add(layout); AcceptButton = create; CancelButton = cancel;
    }
}
