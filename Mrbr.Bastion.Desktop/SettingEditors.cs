using System.ComponentModel;
using System.Drawing.Design;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mrbr.Bastion.Desktop;

internal sealed class PathSettingEditor(string root, bool folder) : UITypeEditor
{
    public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext? context) => UITypeEditorEditStyle.Modal;
    public override object? EditValue(ITypeDescriptorContext? context, IServiceProvider provider, object? value)
    {
        if (folder)
        {
            using var picker = new FolderBrowserDialog { Description = "Select configuration folder", UseDescriptionForTitle = true };
            if (value is string existing && Directory.Exists(existing)) picker.SelectedPath = existing;
            return picker.ShowDialog() == DialogResult.OK ? picker.SelectedPath : value;
        }
        using var dialog = new SaveFileDialog { Title = "Choose file location", OverwritePrompt = false, CheckPathExists = true,
            InitialDirectory = Directory.Exists(root) ? root : "", FileName = value as string ?? "", Filter = "All files (*.*)|*.*" };
        return dialog.ShowDialog() == DialogResult.OK ? dialog.FileName : value;
    }
}

internal sealed class ArraySettingEditor(Type elementType, string root) : UITypeEditor
{
    private static readonly JsonSerializerOptions SessionJson = new() { Converters = { new JsonStringEnumConverter() } };
    public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext? context) => UITypeEditorEditStyle.Modal;
    public override object? EditValue(ITypeDescriptorContext? context, IServiceProvider provider, object? value)
    {
        Array source = value as Array ?? Array.CreateInstance(elementType, 0);
        // Transactional in-memory copy, including session secrets. Cancel leaves the configured collection unchanged.
        Array copy = (Array)JsonSerializer.Deserialize(JsonSerializer.SerializeToUtf8Bytes(source, source.GetType(), SessionJson), source.GetType(), SessionJson)!;
        using var form = new ArraySettingsForm(elementType, copy.Cast<object>().ToList(), root);
        return form.ShowDialog() == DialogResult.OK ? form.Result : value;
    }
}

internal sealed class ArraySettingsForm : Form
{
    private readonly Type _type;
    private readonly List<object> _items;
    private readonly ListBox _list = new() { Dock = DockStyle.Fill };
    private readonly PropertyGrid _grid = new() { Dock = DockStyle.Fill, HelpVisible = true, ToolbarVisible = true };
    private readonly string _root;
    private StringEntry? _text;
    public Array Result { get { CommitText(); var result = Array.CreateInstance(_type, _items.Count); for (int i = 0; i < _items.Count; i++) result.SetValue(_items[i], i); return result; } }
    public ArraySettingsForm(Type type, List<object> items, string root)
    {
        _type = type; _items = items; _root = root;
        Text = "Edit " + type.Name + " collection"; StartPosition = FormStartPosition.CenterParent;
        Size = new(900, 650); MinimumSize = new(700, 500); AutoScaleMode = AutoScaleMode.Dpi;
        var split = new SplitContainer { Size = new(880, 580), Dock = DockStyle.Fill, SplitterDistance = 240 };
        split.Panel1.Controls.Add(_list); split.Panel2.Controls.Add(_grid); Controls.Add(split);
        var commands = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new(8) };
        void Add(string title, Action action) { var b = new Button { Text = title, AutoSize = true }; b.Click += (_, _) => { CommitText(); action(); }; commands.Controls.Add(b); }
        Add("Add", () => { _items.Add(Create(type)); RefreshItems(_items.Count - 1); });
        Add("Remove", () => { int index = _list.SelectedIndex; if (index >= 0) { _items.RemoveAt(index); RefreshItems(Math.Min(index, _items.Count - 1)); } });
        Add("Move up", () => MoveItem(-1)); Add("Move down", () => MoveItem(1));
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, AutoSize = true };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
        commands.Controls.Add(ok); commands.Controls.Add(cancel); Controls.Add(commands); AcceptButton = ok; CancelButton = cancel;
        _list.SelectedIndexChanged += (_, _) =>
        {
            CommitText(); _text = null;
            if (_list.SelectedIndex < 0) { _grid.SelectedObject = null; return; }
            object item = _items[_list.SelectedIndex];
            if (_type == typeof(string)) item = _text = new() { Index = _list.SelectedIndex, Value = (string)item };
            _grid.SelectedObject = new PropertySheet(item, type.Name, _root);
        };
        _grid.PropertyValueChanged += (_, _) => { CommitText(); int index = _list.SelectedIndex; if (index >= 0) _list.Items[index] = Label(_items[index], index); };
        RefreshItems(items.Count == 0 ? -1 : 0);
    }
    private void CommitText() { if (_text is not null && _text.Index < _items.Count) _items[_text.Index] = _text.Value; }
    private static string Label(object item, int index)
    {
        string? name = item as string ?? new[] { "RouteId", "NodeId", "Id", "Path", "Product" }
            .Select(n => item.GetType().GetProperty(n)?.GetValue(item)?.ToString()).FirstOrDefault(v => !string.IsNullOrEmpty(v));
        return $"{index + 1}. {name ?? item.GetType().Name}";
    }
    private void RefreshItems(int selected)
    { _text = null; _list.Items.Clear(); for (int i = 0; i < _items.Count; i++) _list.Items.Add(Label(_items[i], i)); if (selected >= 0) _list.SelectedIndex = selected; }
    private void MoveItem(int delta)
    { int index = _list.SelectedIndex, next = index + delta; if (index >= 0 && next >= 0 && next < _items.Count) { (_items[index], _items[next]) = (_items[next], _items[index]); RefreshItems(next); } }
    private static object Create(Type type)
    {
        if (type == typeof(string)) return "";
        if (type.GetConstructor(Type.EmptyTypes) is { } constructor) return constructor.Invoke(null);
        var positional = type.GetConstructors().Where(c => !c.GetParameters().Any(p => p.ParameterType == type)).OrderBy(c => c.GetParameters().Length).First();
        return positional.Invoke(positional.GetParameters().Select(p => p.HasDefaultValue ? p.DefaultValue
            : p.ParameterType == typeof(string) ? "" : p.ParameterType == typeof(Guid) ? Guid.NewGuid()
            : p.ParameterType == typeof(DateTimeOffset) ? DateTimeOffset.UtcNow
            : p.ParameterType.IsArray ? Array.CreateInstance(p.ParameterType.GetElementType()!, 0)
            : p.ParameterType.IsValueType ? Activator.CreateInstance(p.ParameterType) : null).ToArray());
    }
    private sealed class StringEntry
    {
        [Browsable(false)] public int Index { get; init; }
        [Description("Collection value. Relative file paths use the deployment directory.")] public string Value { get; set; } = "";
    }
}
