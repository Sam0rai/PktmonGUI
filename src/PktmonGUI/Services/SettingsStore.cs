using System;
using System.Collections.Generic;
using System.IO;
using PktmonGUI.Model;
using PktmonGUI.Util;

namespace PktmonGUI.Services
{
    public sealed class AppSettings
    {
        public string WorkingFolder { get; set; }
        /// <summary>The user picked <see cref="WorkingFolder"/> (Change), so it's never replaced by a new default.</summary>
        public bool WorkingFolderChosen { get; set; }
        /// <summary>Adapters are remembered by MAC because component IDs change at reboot.</summary>
        public List<string> LastAdapterMacs { get; set; } = new List<string>();
        public bool FullPacket { get; set; } = true;
        public int SnapLength { get; set; } = 128;
        public int LiveRowCap { get; set; } = 100_000;
        public int CountersRefreshSeconds { get; set; } = 1;
        public bool AutoScroll { get; set; } = true;
        /// <summary>Run the ETW attribution session beside pktmon to show each packet's process.</summary>
        public bool AttributeProcesses { get; set; } = true;
        /// <summary>Live mode: also save the packets as live-*.pcapng in the working folder.</summary>
        public bool SaveLivePcap { get; set; } = true;
        public int LivePcapMaxMb { get; set; } = 2048;
        public CaptureMode LastMode { get; set; } = CaptureMode.Live;
        public int RecordFileSizeMb { get; set; } = 200;
        public LogMode RecordLogMode { get; set; } = LogMode.Circular;
        public List<FilterRule> DraftRules { get; set; } = new List<FilterRule>();
        /// <summary>
        /// <c>pktmon filter list</c> output right after PktmonGUI last applied rules. If the machine
        /// still shows exactly this, the current filters are ours rather than foreign.
        /// </summary>
        public string AppliedFilterListRaw { get; set; }
        /// <summary>The rules PktmonGUI last applied, as it built them (no parsing round trip).</summary>
        public List<FilterRule> AppliedRules { get; set; } = new List<FilterRule>();
        public double? WindowWidth { get; set; }
        public double? WindowHeight { get; set; }
        public bool WindowMaximized { get; set; }
        /// <summary>The left navigation shows icons only.</summary>
        public bool SidebarCollapsed { get; set; }
        public AppTheme Theme { get; set; } = AppTheme.Dark;
        /// <summary>Offer the guided tour after Preflight at each launch, until the user turns it off.</summary>
        public bool ShowTourAtStartup { get; set; } = true;

        /// <summary>The settings.json beside the exe these preferences were last imported from, and when.</summary>
        public string ImportedFrom { get; set; }
        public DateTime? ImportedAt { get; set; }
        /// <summary>SHA-256 of the template last imported; it's imported again only once it changes.</summary>
        public string ImportedHash { get; set; }
        /// <summary>SHA-256 of an untrusted template the user chose to ignore; not offered again until it changes.</summary>
        public string DeclinedHash { get; set; }
    }

    /// <summary>
    /// The live settings, presets and snapshots: %LOCALAPPDATA%\PktmonGUI for the GUI, %ProgramData%\PktmonGUI
    /// for headless mode. Nothing is written beside the exe. A settings.json there is a template an
    /// administrator ships with the tool (see <see cref="SettingsTemplate"/>): the GUI imports its
    /// preferences each time it changes, at once when it's trusted and after the user reviews it when not.
    /// </summary>
    public sealed class SettingsStore
    {
        public SettingsStore(string exeFolder = null)
            : this(exeFolder ?? AppDomain.CurrentDomain.BaseDirectory, DefaultDataFolder, "settings.json", usesTemplate: true) { }

        /// <summary>
        /// A store rooted at a fixed folder with its own settings file. Headless mode keeps its state in
        /// %ProgramData%\PktmonGUI under cli-settings.json, so it never touches a GUI user's settings.
        /// </summary>
        internal SettingsStore(string dataFolder, string settingsFileName)
            : this(AppDomain.CurrentDomain.BaseDirectory, dataFolder, settingsFileName, usesTemplate: false) { }

        internal SettingsStore(string exeFolder, string dataFolder, string settingsFileName, bool usesTemplate,
                               Func<string, SettingsTemplate> readTemplate = null)
        {
            ExeFolder = exeFolder;
            DataFolder = dataFolder;
            _settingsFileName = settingsFileName;
            _usesTemplate = usesTemplate;
            _readTemplate = readTemplate ?? SettingsTemplate.Read;
            // Headless: the caller has made the folder safe (HeadlessPaths.EnsureDataFolder); creating it here
            // would give it %ProgramData%'s "Users may add files".
            if (usesTemplate) Directory.CreateDirectory(DataFolder);
        }

        public static string DefaultDataFolder =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PktmonGUI");

        private readonly string _settingsFileName;
        private readonly bool _usesTemplate;
        private readonly Func<string, SettingsTemplate> _readTemplate;

        public string ExeFolder { get; }
        public string DataFolder { get; }

        public string SettingsPath => Path.Combine(DataFolder, _settingsFileName);
        public string PresetsPath => Path.Combine(DataFolder, "presets.json");
        public string TemplatePath => Path.Combine(ExeFolder, SettingsTemplate.FileName);

        /// <summary>The template beside the exe as last read, or null when there's none (or for headless mode).</summary>
        public SettingsTemplate Template { get; private set; }
        /// <summary>A template not imported yet because it isn't trusted or isn't valid; Preflight offers it.</summary>
        public SettingsTemplate PendingTemplate { get; private set; }
        /// <summary>What the import at startup changed, or null if nothing was imported.</summary>
        public List<SettingChange> Imported { get; private set; }

        public AppSettings Settings { get; private set; } = new AppSettings();

        public AppSettings Load()
        {
            try { Settings = Json.Load<AppSettings>(SettingsPath) ?? new AppSettings(); }
            catch { Settings = new AppSettings(); }
            if (_usesTemplate) CheckTemplate();
            return Settings;
        }

        /// <summary>
        /// Imports the template beside the exe if it changed since the last import (or decline) and can be
        /// trusted; otherwise leaves it in <see cref="PendingTemplate"/>. The user's own changes made since
        /// the last import are kept until the template changes again.
        /// </summary>
        private void CheckTemplate()
        {
            Template = null; PendingTemplate = null; Imported = null;
            try { Template = _readTemplate(ExeFolder); }
            catch { Template = null; }
            if (Template == null) return;
            CopyPresetsOnce();
            if (Template.Hash != null && (Template.Hash == Settings.ImportedHash || Template.Hash == Settings.DeclinedHash)) return;
            if (Template.Usable) Imported = Import(Template);
            else PendingTemplate = Template;
        }

        /// <summary>Copies the template's preferences into the live settings and saves them.</summary>
        public List<SettingChange> Import(SettingsTemplate template)
        {
            var changes = template.ApplyTo(Settings);
            Settings.DeclinedHash = null;
            if (ReferenceEquals(template, PendingTemplate)) PendingTemplate = null;
            Save();
            return changes;
        }

        /// <summary>Leaves the live settings as they are and stops offering this version of the template.</summary>
        public void Decline(SettingsTemplate template)
        {
            Settings.DeclinedHash = template.Hash;
            if (ReferenceEquals(template, PendingTemplate)) PendingTemplate = null;
            Save();
        }

        /// <summary>
        /// presets.json beside a trusted template (left there by a portable copy, or shipped with it) is copied
        /// in once, while there are no presets of the user's own. Presets are only rules to pick from.
        /// </summary>
        private void CopyPresetsOnce()
        {
            try
            {
                var source = Path.Combine(ExeFolder, "presets.json");
                if (!Template.Usable || File.Exists(PresetsPath) || !File.Exists(source)) return;
                if ((File.GetAttributes(source) & FileAttributes.ReparsePoint) != 0) return;
                var presets = Json.Load<List<Preset>>(source);
                if (presets != null && presets.Count > 0) SavePresets(presets);
            }
            catch { /* presets are a convenience */ }
        }

        public void Save()
        {
            try { Json.Save(SettingsPath, Settings); } catch { /* settings are a convenience */ }
        }

        public List<Preset> LoadPresets()
        {
            try { return Json.Load<List<Preset>>(PresetsPath) ?? new List<Preset>(); }
            catch { return new List<Preset>(); }
        }

        public void SavePresets(List<Preset> presets) => Json.Save(PresetsPath, presets);

        internal static bool IsWritable(string folder)
        {
            try
            {
                var probe = Path.Combine(folder, ".pktmongui-write-test-" + Guid.NewGuid().ToString("N"));
                File.WriteAllText(probe, "");
                File.Delete(probe);
                return true;
            }
            catch { return false; }
        }
    }
}
