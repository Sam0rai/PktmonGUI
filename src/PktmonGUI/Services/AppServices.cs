using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using PktmonGUI.Pktmon;

namespace PktmonGUI.Services
{
    /// <summary>What putting the machine's filters back did.</summary>
    public sealed class FilterRestoreResult
    {
        public string Action { get; set; } = "nothing to restore";
        public List<string> Failures { get; } = new List<string>();
        public bool Ok => Failures.Count == 0;
    }

    /// <summary>Composition root: one instance of each service for the app's lifetime.</summary>
    public sealed class AppServices
    {
        public AppServices(SynchronizationContext ui) : this(ui, new SettingsStore(), null) { }

        /// <param name="store">Headless mode passes its own store (see <see cref="SettingsStore(string, string)"/>).</param>
        /// <param name="workingFolder">Where pktmon runs and writes; null uses the saved or default folder.</param>
        internal AppServices(SynchronizationContext ui, SettingsStore store, string workingFolder)
        {
            Store = store;
            Settings = Store.Load();
            if (workingFolder != null)
                Settings.WorkingFolder = workingFolder;
            else if (string.IsNullOrEmpty(Settings.WorkingFolder) || !IsSafeWorkingFolder(Settings.WorkingFolder) ||
                     (!Settings.WorkingFolderChosen && IsLegacyDefaultWorkingFolder(Settings.WorkingFolder)))
                Settings.WorkingFolder = DefaultWorkingFolder();

            Log = new CommandLog(ui);
            if (Store.Imported != null)
                Log.Note($"Imported {Store.Imported.Count} setting{(Store.Imported.Count == 1 ? "" : "s")} from {Store.TemplatePath}" +
                         (Store.Imported.Count > 0 ? ": " + string.Join("; ", Store.Imported) : ""));
            Runner = new PktmonRunner(Log, Settings.WorkingFolder);
            Snapshots = new SnapshotService(Runner, Log, Store.DataFolder);
            Filters = new FilterService(Runner, Snapshots, Store);
            Components = new ComponentResolver(Runner);
            Session = new CaptureSession(Runner, Log);
            Counters = new CountersPoller(Runner) { IntervalSeconds = Settings.CountersRefreshSeconds };
        }

        public SettingsStore Store { get; }
        public AppSettings Settings { get; }
        public CommandLog Log { get; }
        public PktmonRunner Runner { get; }
        public SnapshotService Snapshots { get; }
        public FilterService Filters { get; }
        public ComponentResolver Components { get; }
        public CaptureSession Session { get; }
        public CountersPoller Counters { get; }

        private WiresharkInfo _wireshark;
        private bool _wiresharkLooked;
        public WiresharkInfo Wireshark
        {
            get
            {
                if (!_wiresharkLooked) { _wireshark = WiresharkLocator.Find(); _wiresharkLooked = true; }
                return _wireshark;
            }
        }

        public string WorkingFolder
        {
            get => Settings.WorkingFolder;
            set
            {
                if (!IsSafeWorkingFolder(value)) throw new ArgumentException("Pick a folder outside the Windows directory.");
                var err = PrepareFolder(value, out var setAside);
                if (err != null) throw new InvalidOperationException(err);
                if (setAside != null) Log.Note(setAside);
                Settings.WorkingFolder = value;
                Settings.WorkingFolderChosen = !IsDefaultWorkingFolder(value);
                Runner.WorkingDirectory = value;
                Store.Save();
            }
        }

        /// <summary>
        /// pktmon writes PktMon.etl and temporary files into its current directory; running it from
        /// System32 (the default for an elevated prompt) litters the Windows folder. A UNC path is out too:
        /// pktmon (ETW) can't log to a share, and the elevated process would carry its credentials there.
        /// </summary>
        public static bool IsSafeWorkingFolder(string folder)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(folder)) return false;
                if (folder.StartsWith(@"\\", StringComparison.Ordinal) || folder.StartsWith("//", StringComparison.Ordinal)) return false;
                var full = Path.GetFullPath(folder).TrimEnd('\\') + "\\";
                if (full.StartsWith(@"\\", StringComparison.Ordinal)) return false; // a drive mapped to a share
                var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
                return !full.StartsWith(win, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>
        /// %ProgramData%\PktmonGUI\work: captures hold every packet, so by default they go where only
        /// Administrators (and SYSTEM) can read or change them. Nothing is created here; Preflight creates
        /// the folder when the user continues.
        /// </summary>
        public static string DefaultWorkingFolder() => ProgramDataWorkFolder;

        /// <summary>%ProgramData%\PktmonGUI, shared with headless mode.</summary>
        public static string ProgramDataFolder =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PktmonGUI");

        public static string ProgramDataWorkFolder => Path.Combine(ProgramDataFolder, "work");

        public static bool IsDefaultWorkingFolder(string folder) => SamePath(folder, ProgramDataWorkFolder);

        /// <summary>
        /// "pktmon-work" at a drive root, the earlier default. Folders made in a drive root let every
        /// signed-in user change them, so a saved one the user never picked is replaced by the new default.
        /// </summary>
        internal static bool IsLegacyDefaultWorkingFolder(string folder)
        {
            try
            {
                var full = Path.GetFullPath(folder).TrimEnd('\\');
                var parent = Path.GetDirectoryName(full);
                return string.Equals(Path.GetFileName(full), "pktmon-work", StringComparison.OrdinalIgnoreCase) &&
                       parent != null && string.Equals(parent, Path.GetPathRoot(full), StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private static bool SamePath(string a, string b)
        {
            try { return string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }

        /// <summary>
        /// Why the default working folder (or %ProgramData%\PktmonGUI above it) can't be used, or null.
        /// Changes nothing.
        /// </summary>
        public static string CheckDefaultWorkingFolder() =>
            SecureFolder.Check(ProgramDataFolder) ?? SecureFolder.Check(ProgramDataWorkFolder);

        /// <summary>
        /// Creates a working folder. The default one is made safe (see <see cref="SecureFolder"/>): an
        /// unsafe one is set aside and made again, which <paramref name="setAside"/> reports. This user gets
        /// read access so Explorer can open it. Returns why no folder could be made, or null.
        /// </summary>
        internal static string PrepareFolder(string folder, out string setAside)
        {
            setAside = null;
            if (IsDefaultWorkingFolder(folder))
            {
                SecurityIdentifier me = null;
                try { using (var id = WindowsIdentity.GetCurrent()) me = id.IsSystem ? null : id.User; } catch { }
                var error = SecureFolder.Ensure(ProgramDataFolder, out setAside, me, readerInherits: false);
                if (error != null) return error;
                error = SecureFolder.Ensure(ProgramDataWorkFolder, out var workAside, me, readerInherits: true);
                setAside = setAside ?? workAside;
                return error;
            }
            try
            {
                Directory.CreateDirectory(folder);
                return SettingsStore.IsWritable(folder) ? null : $"{folder} can't be written to.";
            }
            catch (Exception ex) { return $"Couldn't create {folder}: {ex.Message}"; }
        }

        /// <summary>
        /// Creates the working folder; if the picked one can't be written, falls back to the default.
        /// <paramref name="setAside"/> says what unsafe folder was set aside, if any. Returns why no folder
        /// could be used, or null.
        /// </summary>
        public string EnsureWorkingFolder(out string setAside)
        {
            setAside = null;
            string error = null;
            foreach (var candidate in new[] { WorkingFolder, DefaultWorkingFolder() }.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (string.IsNullOrEmpty(candidate) || !IsSafeWorkingFolder(candidate)) continue;
                error = PrepareFolder(candidate, out var aside);
                setAside = setAside ?? aside;
                if (error != null) continue;
                if (aside != null) Log.Note(aside);
                Settings.WorkingFolder = candidate;
                Settings.WorkingFolderChosen = !IsDefaultWorkingFolder(candidate);
                Runner.WorkingDirectory = candidate;
                Store.Save();
                return null;
            }
            return error ?? "No working folder could be used.";
        }

        /// <summary>
        /// End of session, per the "always stop and restore" rule: stop pktmon if we started it,
        /// then replay the snapshot of foreign filters if one is pending.
        /// </summary>
        public async Task ShutdownAsync()
        {
            Counters.Stop();
            try
            {
                if (Session.State == SessionState.Running || Session.State == SessionState.Starting)
                    await Session.StopAsync("PktmonGUI closed").ConfigureAwait(false);
            }
            catch { }
            // The attribution ETW session would outlive us; make sure it's gone.
            try { Session.Attribution?.Stop(); } catch { }
            await RestoreMachineFiltersAsync().ConfigureAwait(false);
            Store.Save();
        }

        /// <summary>
        /// Leaves the machine's filters as they were found: replays the pending snapshot of foreign
        /// filters, or, with none, takes PktmonGUI's own rules off. Never throws.
        /// </summary>
        public async Task<FilterRestoreResult> RestoreMachineFiltersAsync()
        {
            var result = new FilterRestoreResult();
            try
            {
                if (Snapshots.HasPendingRestore)
                {
                    result.Action = "restored the machine's filters from the snapshot";
                    result.Failures.AddRange(await Snapshots.RestoreAsync().ConfigureAwait(false));
                }
                else
                {
                    // No snapshot means the machine had no foreign filters (or the user declined to keep them).
                    // Leave it as found: take PktmonGUI's own rules off. The draft is kept for next time.
                    var now = await Filters.ReadAsync().ConfigureAwait(false);
                    if (now.AreOurs)
                    {
                        result.Action = "removed PktmonGUI's rules";
                        var r = await Runner.RunAsync(PktmonCommand.FilterRemove("PktmonGUI's rules removed on exit; the draft is kept")).ConfigureAwait(false);
                        if (!r.Success) result.Failures.Add("pktmon filter remove failed: " + r.Output);
                    }
                }
            }
            catch (Exception ex) { result.Failures.Add(ex.Message); }
            return result;
        }

        /// <summary>Synchronous best effort for crash handlers.</summary>
        public void EmergencyShutdown()
        {
            try { Task.Run(ShutdownAsync).Wait(TimeSpan.FromSeconds(20)); } catch { }
        }
    }
}
