using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using PktmonGUI.Model;
using PktmonGUI.Util;

namespace PktmonGUI.Services
{
    /// <summary>One preference a template sets, as shown before importing it.</summary>
    public sealed class SettingChange
    {
        public string Label { get; set; }
        public string From { get; set; }
        public string To { get; set; }
        public override string ToString() => $"{Label}: {From} → {To}";
    }

    /// <summary>
    /// A settings.json beside the exe: a read-only template an administrator ships with the tool. The GUI
    /// imports its preferences into the live settings in %LOCALAPPDATA%; headless mode takes its capture
    /// defaults from it. Both run elevated (or as SYSTEM), so the file is trusted only where no other account
    /// could have written it: a local folder owned by Administrators that nobody else can change, and a file
    /// that is no link and nobody else can change either. It's checked and read through one handle, so it
    /// can't be swapped in between. Only preferences are taken, never this machine's state (which filters
    /// are PktmonGUI's, adapters, snapshots), and every value is checked as if typed in.
    /// </summary>
    public sealed class SettingsTemplate
    {
        public const string FileName = "settings.json";
        internal const int MaxBytes = 1 << 20;

        public string Path { get; private set; }
        /// <summary>SHA-256 of the file, so an import happens once per version of it.</summary>
        public string Hash { get; private set; }
        /// <summary>Why another account could have written it, or null. Its values are still read, for review.</summary>
        public string Untrusted { get; private set; }
        /// <summary>Why it can't be used at all (unreadable, a link, not settings JSON, a bad value), or null.</summary>
        public string Error { get; private set; }
        public bool Usable => Error == null && Untrusted == null;

        internal AppSettings Values { get; private set; }
        private HashSet<string> _present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>The template beside <paramref name="exeFolder"/>, or null when there's none.</summary>
        public static SettingsTemplate Read(string exeFolder) => Read(exeFolder, SecureFolder.AdminsSid);

        /// <param name="owner">Who may own the folder and file besides SYSTEM, Administrators and TrustedInstaller (tests).</param>
        internal static SettingsTemplate Read(string exeFolder, SecurityIdentifier owner)
        {
            var path = System.IO.Path.Combine(exeFolder, FileName);
            if (!Exists(path)) return null;
            var t = new SettingsTemplate { Path = path };
            t.Untrusted = LocationProblem(exeFolder) ?? SecureFolder.Check(exeFolder, owner);
            string text;
            try { text = t.ReadChecked(owner); }
            catch (Exception ex) { t.Error = $"{path} couldn't be read: {ex.Message}"; return t; }
            if (text == null) return t;
            t.Parse(text);
            return t;
        }

        /// <summary>A share (or a drive mapped to one): BUILTIN\Administrators in its ACL means the file server's.</summary>
        internal static string LocationProblem(string folder)
        {
            try
            {
                if (folder.StartsWith(@"\\", StringComparison.Ordinal)) return $"{folder} is on a network share.";
                var type = new DriveInfo(System.IO.Path.GetPathRoot(System.IO.Path.GetFullPath(folder))).DriveType;
                return type == DriveType.Fixed || type == DriveType.Removable ? null : $"{folder} is on a {type.ToString().ToLowerInvariant()} drive.";
            }
            catch (Exception ex) { return $"{folder} couldn't be checked: {ex.Message}"; }
        }

        /// <summary>
        /// Opens the file itself (a link isn't followed), checks it on that handle, and reads it from the
        /// same handle. Null (with <see cref="Error"/> set) when it must not be read.
        /// </summary>
        private string ReadChecked(SecurityIdentifier owner)
        {
            // Write-owner lets a trusted file copied in by an admin (who then owns it) be handed to Administrators.
            using (var handle = Open(Path, Untrusted == null))
            using (var fs = new FileStream(handle, FileAccess.Read))
            {
                if (!GetFileInformationByHandle(handle, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var attrs = (FileAttributes)info.FileAttributes;
                if ((attrs & FileAttributes.ReparsePoint) != 0) { Error = $"{Path} is a link."; return null; }
                if ((attrs & FileAttributes.Directory) != 0) { Error = $"{Path} is a folder."; return null; }

                if (Untrusted == null) Untrusted = CheckFile(fs, owner);
                if (fs.Length > MaxBytes) { Error = $"{Path} is larger than {MaxBytes >> 20} MB."; return null; }
                var bytes = new byte[fs.Length];
                int read = 0;
                for (int n; read < bytes.Length && (n = fs.Read(bytes, read, bytes.Length - read)) > 0;) read += n;
                using (var sha = SHA256.Create())
                    Hash = BitConverter.ToString(sha.ComputeHash(bytes, 0, read)).Replace("-", "");
                return new UTF8Encoding(false).GetString(bytes, 0, read).TrimStart('\uFEFF');
            }
        }

        /// <summary>Why another account could change the file, or null. An untrusted owner is replaced by Administrators.</summary>
        private string CheckFile(FileStream fs, SecurityIdentifier owner)
        {
            var sec = fs.GetAccessControl();
            var writer = SecureFolder.UntrustedWriter(sec, owner);
            if (writer != null) return $"{Path} lets {SecureFolder.Describe(writer)} change it.";
            var actual = sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (SecureFolder.IsTrusted(actual, owner)) return null;
            try
            {
                var o = new FileSecurity();
                o.SetOwner(SecureFolder.AdminsSid);
                fs.SetAccessControl(o);
            }
            catch (Exception ex) { return $"{Path} belongs to {SecureFolder.Describe(actual)}, and Administrators couldn't be made its owner ({ex.Message})."; }
            sec = fs.GetAccessControl();
            writer = SecureFolder.UntrustedWriter(sec, owner);
            return writer != null ? $"{Path} lets {SecureFolder.Describe(writer)} change it." : null;
        }

        private void Parse(string text)
        {
            try
            {
                using (var doc = JsonDocument.Parse(text, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }))
                {
                    if (doc.RootElement.ValueKind != JsonValueKind.Object) { Error = $"{Path} isn't a settings file (no JSON object)."; return; }
                    foreach (var p in doc.RootElement.EnumerateObject()) _present.Add(p.Name);
                }
                Values = Json.Deserialize<AppSettings>(text);
            }
            catch (Exception ex) { Error = $"{Path} isn't valid settings JSON: {ex.Message}"; Values = null; return; }
            var problems = Validate().ToList();
            if (problems.Count > 0) Error = $"{Path}: {string.Join(" ", problems)}";
        }

        // ---- What a template may set ------------------------------------------------------

        private sealed class Field
        {
            public string Name;
            public string Label;
            public Func<AppSettings, object> Get;
            public Func<AppSettings, string> Show;
            public Action<AppSettings, AppSettings> Copy;
        }

        private static Field F<T>(string name, string label, Func<AppSettings, T> get, Action<AppSettings, T> set, Func<T, string> show = null) =>
            new Field { Name = name, Label = label, Get = s => get(s), Show = s => show != null ? show(get(s)) : Show(get(s)), Copy = (from, to) => set(to, get(from)) };

        private static string Show(object v)
        {
            switch (v)
            {
                case null: return "(none)";
                case bool b: return b ? "on" : "off";
                case double d: return d.ToString("0", CultureInfo.InvariantCulture);
                case IFormattable f: return f.ToString(null, CultureInfo.InvariantCulture);
                default: return v.ToString();
            }
        }

        private static string ShowRules(List<FilterRule> rules) =>
            rules == null || rules.Count == 0 ? "(none)" : $"{rules.Count}: " + string.Join("; ", rules.Select(r => r?.ArgsSummary));

        /// <summary>Preferences only. This machine's state (applied filters, adapters, snapshots) never comes from a template.</summary>
        private static readonly Field[] Fields =
        {
            F("workingFolder", "Working folder", s => s.WorkingFolder, (s, v) => { s.WorkingFolder = v; s.WorkingFolderChosen = !AppServices.IsDefaultWorkingFolder(v); }),
            F("fullPacket", "Full packets", s => s.FullPacket, (s, v) => s.FullPacket = v),
            F("snapLength", "Snap length (bytes)", s => s.SnapLength, (s, v) => s.SnapLength = v),
            F("liveRowCap", "Live row limit", s => s.LiveRowCap, (s, v) => s.LiveRowCap = v),
            F("countersRefreshSeconds", "Counters refresh (s)", s => s.CountersRefreshSeconds, (s, v) => s.CountersRefreshSeconds = v),
            F("autoScroll", "Auto-scroll", s => s.AutoScroll, (s, v) => s.AutoScroll = v),
            F("attributeProcesses", "Process attribution", s => s.AttributeProcesses, (s, v) => s.AttributeProcesses = v),
            F("saveLivePcap", "Save live pcapng", s => s.SaveLivePcap, (s, v) => s.SaveLivePcap = v),
            F("livePcapMaxMb", "Live pcapng limit (MB)", s => s.LivePcapMaxMb, (s, v) => s.LivePcapMaxMb = v),
            F("lastMode", "Capture mode", s => s.LastMode, (s, v) => s.LastMode = v),
            F("recordFileSizeMb", "Record size (MB)", s => s.RecordFileSizeMb, (s, v) => s.RecordFileSizeMb = v),
            F("recordLogMode", "Record log mode", s => s.RecordLogMode, (s, v) => s.RecordLogMode = v),
            F("draftRules", "Filter rules", s => s.DraftRules, (s, v) => s.DraftRules = v.Select(r => r.Clone()).ToList(), ShowRules),
            F("theme", "Theme", s => s.Theme, (s, v) => s.Theme = v),
            F("sidebarCollapsed", "Sidebar collapsed", s => s.SidebarCollapsed, (s, v) => s.SidebarCollapsed = v),
            F("showTourAtStartup", "Tour at startup", s => s.ShowTourAtStartup, (s, v) => s.ShowTourAtStartup = v),
            F("windowWidth", "Window width", s => s.WindowWidth, (s, v) => s.WindowWidth = v),
            F("windowHeight", "Window height", s => s.WindowHeight, (s, v) => s.WindowHeight = v),
            F("windowMaximized", "Window maximized", s => s.WindowMaximized, (s, v) => s.WindowMaximized = v),
        };

        /// <summary>
        /// <paramref name="live"/>'s preferences as a template: the fields a template may set, and none of this
        /// machine's state (adapters' MACs, applied filters, imports). The working folder is left out while
        /// it's the default, so each machine keeps its own.
        /// </summary>
        internal static Dictionary<string, object> ExportValues(AppSettings live)
        {
            var values = new Dictionary<string, object>();
            foreach (var f in Fields)
            {
                if (f.Name == "workingFolder" && (string.IsNullOrEmpty(live.WorkingFolder) || AppServices.IsDefaultWorkingFolder(live.WorkingFolder))) continue;
                var v = f.Get(live);
                if (v != null) values[f.Name] = v;
            }
            return values;
        }

        /// <summary>Writes <paramref name="live"/>'s preferences to <paramref name="path"/> as a template.</summary>
        public static void Export(AppSettings live, string path) => Json.Save(path, ExportValues(live));

        /// <summary>True when the template names this setting (by its JSON name, e.g. "recordFileSizeMb").</summary>
        internal bool Sets(string name) => Values != null && _present.Contains(name);

        private IEnumerable<string> Validate()
        {
            var v = Values;
            if (Sets("workingFolder"))
            {
                var f = v.WorkingFolder;
                bool full = f != null && f.Length >= 3 && char.IsLetter(f[0]) && f[1] == ':' && (f[2] == '\\' || f[2] == '/');
                if (!full || !AppServices.IsSafeWorkingFolder(f))
                    yield return $"workingFolder \"{f}\" must be a full local path outside the Windows folder, e.g. D:\\Captures.";
            }
            if (Sets("snapLength") && v.SnapLength < 1) yield return "snapLength must be at least 1.";
            if (Sets("liveRowCap") && v.LiveRowCap < 1000) yield return "liveRowCap must be at least 1000.";
            if (Sets("countersRefreshSeconds") && (v.CountersRefreshSeconds < 1 || v.CountersRefreshSeconds > 3600)) yield return "countersRefreshSeconds must be 1 to 3600.";
            if (Sets("livePcapMaxMb") && v.LivePcapMaxMb < 1) yield return "livePcapMaxMb must be at least 1.";
            if (Sets("recordFileSizeMb") && v.RecordFileSizeMb < 1) yield return "recordFileSizeMb must be at least 1.";
            if (Sets("lastMode") && !Enum.IsDefined(typeof(CaptureMode), v.LastMode)) yield return "lastMode isn't a capture mode.";
            if (Sets("recordLogMode") && v.RecordLogMode != LogMode.Circular && v.RecordLogMode != LogMode.MultiFile)
                yield return "recordLogMode must be Circular or MultiFile.";
            if (Sets("theme") && !Enum.IsDefined(typeof(AppTheme), v.Theme)) yield return "theme must be Dark, Light or System.";
            if (Sets("windowWidth") && !(v.WindowWidth > 0)) yield return "windowWidth must be more than 0.";
            if (Sets("windowHeight") && !(v.WindowHeight > 0)) yield return "windowHeight must be more than 0.";
            if (Sets("draftRules"))
            {
                var rules = v.DraftRules ?? new List<FilterRule>();
                if (rules.Count > FilterRule.MaxRules) yield return $"draftRules has {rules.Count} rules; pktmon allows at most {FilterRule.MaxRules}.";
                for (int i = 0; i < rules.Count; i++)
                {
                    if (rules[i] == null) { yield return $"draftRules[{i}] is empty."; continue; }
                    foreach (var p in rules[i].Validate()) yield return $"draftRules[{i}]: {p}";
                }
            }
        }

        /// <summary>What importing would change in <paramref name="live"/>; changes nothing.</summary>
        public List<SettingChange> Diff(AppSettings live) =>
            Values == null ? new List<SettingChange>() :
            Fields.Where(f => Sets(f.Name) && f.Show(live) != f.Show(Values))
                  .Select(f => new SettingChange { Label = f.Label, From = f.Show(live), To = f.Show(Values) }).ToList();

        /// <summary>Copies the template's preferences into <paramref name="live"/> and returns what changed.</summary>
        public List<SettingChange> ApplyTo(AppSettings live)
        {
            if (Error != null) throw new InvalidOperationException(Error);
            var changes = Diff(live);
            foreach (var f in Fields)
                if (Sets(f.Name)) f.Copy(Values, live);
            live.ImportedFrom = Path;
            live.ImportedHash = Hash;
            live.ImportedAt = DateTime.Now;
            return changes;
        }

        // ---- Win32 ------------------------------------------------------------------------

        private static bool Exists(string path)
        {
            try { File.GetAttributes(path); return true; } // a link counts, so it's reported rather than ignored
            catch { return false; }
        }

        private const uint GenericRead = 0x80000000, ReadControl = 0x00020000, WriteOwner = 0x00080000;
        private const uint FileShareRead = 1, OpenExisting = 3, FlagOpenReparsePoint = 0x00200000;
        private const int ErrorAccessDenied = 5;

        /// <summary>The file itself (FILE_FLAG_OPEN_REPARSE_POINT), shared for reading only so it can't change while open.</summary>
        private static SafeFileHandle Open(string path, bool writeOwner)
        {
            var h = CreateFileW(path, GenericRead | ReadControl | (writeOwner ? WriteOwner : 0), FileShareRead, IntPtr.Zero, OpenExisting, FlagOpenReparsePoint, IntPtr.Zero);
            if (h.IsInvalid && writeOwner && Marshal.GetLastWin32Error() == ErrorAccessDenied)
            {
                h.Dispose();
                h = CreateFileW(path, GenericRead | ReadControl, FileShareRead, IntPtr.Zero, OpenExisting, FlagOpenReparsePoint, IntPtr.Zero);
            }
            if (h.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                h.Dispose();
                throw new Win32Exception(error);
            }
            return h;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
            public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
                                                         uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);
    }
}
