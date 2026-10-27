using System.ComponentModel;
using System.ComponentModel.Design;
using System.Drawing.Design;
using System.Reflection;
using System.Text.RegularExpressions;
using Mrbr.Bastion.Configuration;

namespace Mrbr.Bastion.Desktop;

/// <summary>Presentation metadata around real configuration objects, without adding UI dependencies to hosts.</summary>
[TypeConverter(typeof(ExpandableObjectConverter))]
public sealed class PropertySheet : Component, ICustomTypeDescriptor
{
    public object Value { get; }
    public string BaseDirectory { get; }
    private readonly string _name;
    public PropertySheet(object value, string name, string baseDirectory, IEnumerable<DesignerVerb>? verbs = null)
    {
        Value = value; _name = name; BaseDirectory = baseDirectory;
        if (verbs is not null) Site = new VerbSite(this, verbs);
    }
    public override string ToString() => _name;
    public AttributeCollection GetAttributes() => AttributeCollection.Empty;
    public string GetClassName() => Value.GetType().Name;
    public string GetComponentName() => _name;
    public TypeConverter GetConverter() => new ExpandableObjectConverter();
    public EventDescriptor? GetDefaultEvent() => null;
    public PropertyDescriptor? GetDefaultProperty() => null;
    public object? GetEditor(Type editorBaseType) => null;
    public EventDescriptorCollection GetEvents() => EventDescriptorCollection.Empty;
    public EventDescriptorCollection GetEvents(Attribute[]? attributes) => EventDescriptorCollection.Empty;
    public PropertyDescriptorCollection GetProperties() => GetProperties(null);
    public PropertyDescriptorCollection GetProperties(Attribute[]? attributes) => new(Value.GetType().GetProperties()
        .Where(p => p.CanRead && p.GetIndexParameters().Length == 0 && p.GetCustomAttribute<BrowsableAttribute>()?.Browsable != false)
        .Select(p => (PropertyDescriptor)new SettingProperty(p, BaseDirectory)).ToArray());
    public object GetPropertyOwner(PropertyDescriptor? pd) => this;

    public static string Friendly(string name) => Regex.Replace(name, "(?<=[a-z0-9])([A-Z])", " $1");
    private sealed class SettingProperty(PropertyInfo property, string baseDirectory) : PropertyDescriptor(property.Name, property.GetCustomAttributes<Attribute>().ToArray())
    {
        private readonly bool _complex = !property.PropertyType.IsValueType && property.PropertyType != typeof(string)
            && property.PropertyType != typeof(Uri) && !property.PropertyType.IsArray;
        public override Type ComponentType => typeof(PropertySheet);
        public override Type PropertyType => _complex ? typeof(PropertySheet) : property.PropertyType;
        public override string DisplayName => Friendly(Name);
        public override bool IsReadOnly => !property.CanWrite || property.GetCustomAttribute<ReadOnlyAttribute>()?.IsReadOnly == true;
        public override string Category => ProfileStorage.SecretNames.Contains(Name) ? "Security / session only"
            : Name.Contains("Path", StringComparison.Ordinal) || Name.Contains("Directory", StringComparison.Ordinal) ? "Files and storage"
            : Name.StartsWith("Maximum", StringComparison.Ordinal) ? "Capacity limits"
            : Name.EndsWith("Seconds", StringComparison.Ordinal) || Name.EndsWith("Minutes", StringComparison.Ordinal) ? "Timing"
            : "Settings";
        public override string Description => property.GetCustomAttribute<DescriptionAttribute>()?.Description ?? HelpText.For(Name);
        public override AttributeCollection Attributes => ProfileStorage.SecretNames.Contains(Name)
            ? new(base.Attributes.Cast<Attribute>().Append(new PasswordPropertyTextAttribute(true)).ToArray()) : base.Attributes;
        public override object? GetValue(object? component)
        {
            object? result = property.GetValue(((PropertySheet)component!).Value);
            return _complex && result is not null ? new PropertySheet(result, DisplayName, baseDirectory) : result;
        }
        public override void SetValue(object? component, object? value)
        {
            property.SetValue(((PropertySheet)component!).Value, value is PropertySheet sheet ? sheet.Value : value);
            OnValueChanged(component, EventArgs.Empty);
        }
        public override object? GetEditor(Type editorBaseType)
        {
            if (editorBaseType == typeof(UITypeEditor))
            {
                if (property.PropertyType.IsArray) return new ArraySettingEditor(property.PropertyType.GetElementType()!, baseDirectory);
                if (property.PropertyType == typeof(string) && (Name.Contains("Path", StringComparison.Ordinal)
                    || Name.EndsWith("Directory", StringComparison.Ordinal) || Name == "Root" || Name.EndsWith("Executable", StringComparison.Ordinal)))
                    return new PathSettingEditor(baseDirectory, Name.EndsWith("Directory", StringComparison.Ordinal) || Name == "Root");
            }
            return base.GetEditor(editorBaseType);
        }
        public override bool CanResetValue(object component) => false;
        public override void ResetValue(object component) { }
        public override bool ShouldSerializeValue(object component) => true;
    }

    private sealed class VerbSite(IComponent component, IEnumerable<DesignerVerb> verbs) : ISite
    {
        private readonly Commands _commands = new(verbs);
        public IComponent Component => component;
        public IContainer? Container => null;
        public bool DesignMode => false;
        public string? Name { get; set; }
        public object? GetService(Type serviceType) => serviceType == typeof(IMenuCommandService) ? _commands : null;
    }
    private sealed class Commands(IEnumerable<DesignerVerb> verbs) : IMenuCommandService
    {
        public DesignerVerbCollection Verbs { get; } = new(verbs.ToArray());
        public void AddVerb(DesignerVerb verb) => Verbs.Add(verb);
        public void RemoveVerb(DesignerVerb verb) => Verbs.Remove(verb);
        public void AddCommand(MenuCommand command) { }
        public void RemoveCommand(MenuCommand command) { }
        public MenuCommand? FindCommand(CommandID commandID) => null;
        public bool GlobalInvoke(CommandID commandID) => false;
        public void ShowContextMenu(CommandID menuID, int x, int y) { }
    }
}

internal static class HelpText
{
    public const string Overview = "Configure a deployment\n\n1. Choose the deployment folder and built binaries.\n2. Configure the required signing key save locations, then create or verify the pairs.\n3. Initialize selected ledgers and enroll them. Existing ledger identities and historical trust are preserved.\n4. Configure receiver HTTPS. Use an existing trusted PFX, or explicitly trust a local development certificate. Signing PEMs are not HTTPS certificates.\n5. Enable Users authentication and create the first administrator while the server is stopped.\n6. Validate, save the profile, export runtime configuration and start selected components.\n\nRun this app as Administrator for live ETW collection. Stopping sends a current-user-only authenticated local request so collectors can drain accepted work. Force stop is separate and can lose uncommitted observations.\n\nEach agent has its own outbox and enrollment. A new profile does not reset existing ledgers. Remote nodes require copying their public verification keys and using a reachable HTTPS receiver address.\n\nPasswords, tokens and signing secrets are session-only and are never exported into JSON. They are passed through the receiver's environment. Re-enter them after reopening a profile, or provision them through the service environment.\n\nThe control panel manages local child processes, not Windows service installation or remote execution. CVE matching requires reviewed product mappings; manage those through the authorized dashboard.\n\nSelect any property for its description; press F1 for contextual help. Collection ellipsis buttons open add/remove/reorder editors. PropertyGrid links and the Commands menu act on the selected section.\n\nCache retention\n\nBoth agent sections expose Retention and resident Maximum Stored Payload Bytes. Archiving is disabled by default. Choose archive storage and limits before enabling it. Only a verified settled prefix is archived; pending blocks remain resident. Keep archives with the database when backing up or restoring.\n\nStorage commands verify history, archive a bounded pass, or compact selected caches while components are stopped. Archiving saves the profile first. Published history is never expired automatically. Relative archive roots resolve against the cache database folder; an empty path reuses an existing recorded location.";
    public static string For(string name)
    {
        if (ProfileStorage.SecretNames.Contains(name)) return "Session-only secret. Masked in the grid; omitted from profiles and exported files. Supply again after reload or through the receiver environment.";
        return name switch
        {
            "Nodes" => "Explicit trusted node and ledger enrollments. Initialize and enroll creates entries for the selected local agents; add remote entries with their public PEM only.",
            "PublicKeys" => "Trusted SubjectPublicKeyInfo public PEM files. Preserve historical keys while retained blocks depend on them.",
            "LedgerId" => "Exact GUID printed by outbox inspection. Never invent or reset this value for an existing database.",
            "ProcessEvents" => "Enable live ETW process inventory and correlated parent context. Requires Administrator privileges; periodic snapshots alone do not establish lineage.",
            "Retention" => "Configure settled-prefix archiving. Unsettled blocks remain resident. Published archives and their receipts remain part of full cache history. Storage commands require stopped agents; keep archives with the database for backup and restore.",
            "Crawlers" => "Configurable file/archive tasks. Choose a stable unique ID, enable explicitly, and set an absolute root. Checkpoints resume unfinished work.",
            "Mappings" => "Reviewed software/CPE mappings. Prefer dashboard review with an identified analyst; product names alone do not establish a CVE match.",
            "Email" => "SMTP routes, one recipient per route. Use a unique RouteId, From/To mailboxes and TLS. Passwords are session-only.",
            "Webhooks" => "HTTPS destinations with optional bearer authentication and HMAC signatures. Secret values are session-only. Consumers should deduplicate delivery IDs.",
            "Enabled" => "Enable this feature. Configure its dependencies, paths and limits before starting.",
            "AuthenticationMode" => "Users provides per-user roles and revocable sessions. LegacyToken is an explicit migration option.",
            "AllowInsecureLoopback" => "Development-only loopback exception. It does not permit insecure remote delivery.",
            "ReplayExistingEvents" => "Opt in to replay for a newly configured route; this can send older retained alerts.",
            "IntelligenceEnabled" => "Enable outbound NVD refresh. Configure reviewed product mappings and monitor coverage/freshness.",
            _ when name.StartsWith("Maximum", StringComparison.Ordinal) => "Upper capacity/concurrency bound for " + PropertySheet.Friendly(name) + ". Quotas fail explicitly; retained evidence is not silently purged.",
            _ when name.EndsWith("Seconds", StringComparison.Ordinal) || name.EndsWith("Minutes", StringComparison.Ordinal) => "Interval or timeout for " + PropertySheet.Friendly(name) + ". Validation checks supported ranges before launch where available.",
            _ when name.Contains("Path", StringComparison.Ordinal) => "File location. Relative paths resolve against the deployment/configuration directory. Keep each database and signing key in its intended location.",
            _ => "Configure " + PropertySheet.Friendly(name) + ". This maps to the runtime host setting with the same name. Validate and export after editing."
        };
    }
}
