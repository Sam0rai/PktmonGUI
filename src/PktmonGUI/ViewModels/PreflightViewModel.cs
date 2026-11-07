using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using PktmonGUI.Model;
using PktmonGUI.Parsing;
using PktmonGUI.Pktmon;
using PktmonGUI.Services;
using PktmonGUI.Util;

namespace PktmonGUI.ViewModels
{
    public sealed partial class CheckItem : ObservableObject
    {
        [ObservableProperty] private CheckState _state = CheckState.Pending;
        [ObservableProperty] private string _title;
        [ObservableProperty] private string _before;
        [ObservableProperty] private string _mono;
        [ObservableProperty] private string _after;
        [ObservableProperty] private string _actionText;
        [ObservableProperty] private IRelayCommand _action;
        [ObservableProperty] private string _action2Text;
        [ObservableProperty] private IRelayCommand _action2;
        [ObservableProperty] private string _action3Text;
        [ObservableProperty] private IRelayCommand _action3;
    }

    public sealed partial class AdapterItem : ObservableObject
    {
        public AdapterItem(Component c) { Component = c; }
        public Component Component { get; }
        [ObservableProperty] private bool _isSelected;

        public string Name => Component.Name;
        public string Subtitle
        {
            get
            {
                var parts = new List<string>();
                if (Component.IsWireless) parts.Add("Wireless");
                else if (Component.IsAdapter) parts.Add(Component.Type == "Miniport" ? "Ethernet" : Component.Type);
                else parts.Add(Component.Type);
                if (!string.IsNullOrEmpty(Component.ConnectionName)) parts.Add(Component.ConnectionName);
                else if (!string.IsNullOrEmpty(Component.Group) && Component.Group != Component.Name) parts.Add(Component.Group);
                return string.Join(" · ", parts);
            }
        }
        public string Warning => Component.IsWireless ? "etl2pcap output from Wi-Fi may not open cleanly in Wireshark" : null;
        public string Mac => Component.MacAddress ?? "";
        public string IPv4 => Component.IPv4 ?? "";
        public string Link => Component.LinkText;
        public bool LinkUp => Component.LinkStatus == "Up";
        public int Id => Component.Id;
    }

    public sealed partial class PreflightViewModel : ObservableObject
    {
        private readonly MainViewModel _main;
        private AppServices S => _main.Services;

        public PreflightViewModel(MainViewModel main)
        {
            _main = main;
            Checks = new ObservableCollection<CheckItem> { Elevation, PktmonCheck, FolderCheck, SettingsCheck, FiltersCheck };
        }

        public ObservableCollection<CheckItem> Checks { get; }
        public CheckItem Elevation { get; } = new CheckItem { Title = "Elevated session" };
        public CheckItem PktmonCheck { get; } = new CheckItem { Title = "pktmon present" };
        public CheckItem FolderCheck { get; } = new CheckItem { Title = "Working folder" };
        public CheckItem SettingsCheck { get; } = new CheckItem { Title = "Settings" };
        public CheckItem FiltersCheck { get; } = new CheckItem { Title = "Machine filters" };
        private CheckItem _restoreCheck;

        public ObservableCollection<AdapterItem> Adapters { get; } = new ObservableCollection<AdapterItem>();
        public CommandLog Log => S.Log;

        [ObservableProperty] private bool _isRunning;
        [ObservableProperty] private bool _showAllComponents;
        [ObservableProperty] private string _adapterError;
        [ObservableProperty] private bool _hasMutated;

        public bool CanContinue => !IsRunning && Checks.All(c => c.State != CheckState.Fail && c.State != CheckState.Pending)
                                   && Adapters.Any(a => a.IsSelected);

        public string ContinueHint =>
            Checks.Any(c => c.State == CheckState.Fail) ? "Fix the red items first." :
            !Adapters.Any(a => a.IsSelected) ? "Pick at least one adapter to capture on." : null;

        partial void OnShowAllComponentsChanged(bool value) => _ = LoadAdaptersAsync();

        private void RaiseContinue()
        {
            OnPropertyChanged(nameof(CanContinue));
            OnPropertyChanged(nameof(ContinueHint));
            ContinueCommand.NotifyCanExecuteChanged();
        }

        [RelayCommand]
        public async Task RunChecksAsync()
        {
            if (IsRunning) return;
            IsRunning = true;
            foreach (var c in Checks) c.State = CheckState.Pending;
            RaiseContinue();
            try
            {
                CheckElevation();
                bool pktmonOk = await CheckPktmonAsync();
                CheckFolder();
                CheckSettings();
                if (pktmonOk)
                {
                    StopLeftoverEtwSession();
                    await CheckFiltersAsync();
                    CheckUnrestoredSnapshots();
                    await LoadAdaptersAsync();
                }
                else
                {
                    FiltersCheck.State = CheckState.Fail;
                    FiltersCheck.Before = "Needs pktmon.";
                    FiltersCheck.Mono = null; FiltersCheck.After = null;
                }
            }
            finally
            {
                IsRunning = false;
                HasMutated = S.Log.HasMutated;
                RaiseContinue();
                _main.RefreshSessionCard();
            }
        }

        private void CheckElevation()
        {
            var id = WindowsIdentity.GetCurrent();
            bool admin = _main.IsAdministrator;
            Elevation.State = admin ? CheckState.Ok : CheckState.Fail;
            Elevation.Before = "Running as ";
            Elevation.Mono = id.Name;
            Elevation.After = admin ? " · pktmon requires Administrator" : " · not elevated: restart PktmonGUI as Administrator";
        }

        /// <summary>Real-time mode, --json and the current syntax arrived with Windows 10 2004 (build 19041).</summary>
        public const int MinimumBuild = SystemChecks.MinimumBuild;

        private async Task<bool> CheckPktmonAsync()
        {
            var os = SystemChecks.OsInfo();
            var osText = SystemChecks.OsText();
            PktmonCheck.Action = null; PktmonCheck.ActionText = null;

            if (!PktmonRunner.PktmonExists)
            {
                PktmonCheck.State = CheckState.Fail;
                PktmonCheck.Before = osText + " · ";
                PktmonCheck.Mono = PktmonRunner.PktmonPath;
                PktmonCheck.After = " not found";
                return false;
            }
            if (os.build > 0 && os.build < MinimumBuild)
            {
                PktmonCheck.State = CheckState.Fail;
                PktmonCheck.Before = osText + " · this pktmon predates real-time mode and the current syntax. PktmonGUI needs Windows 10 2004 / Server 2022 or later (build ";
                PktmonCheck.Mono = MinimumBuild.ToString();
                PktmonCheck.After = "+).";
                return false;
            }

            var r = await S.Runner.RunAsync(PktmonCommand.Status());
            var status = StatusParser.Parse(r.Output);
            PktmonCheck.Before = osText + " · ";
            PktmonCheck.Mono = "pktmon status";
            if (r.Output.IndexOf("Access is denied", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                PktmonCheck.State = CheckState.Fail;
                PktmonCheck.After = " was denied: PktmonGUI must run elevated";
                return false;
            }
            if (!status.Running)
            {
                PktmonCheck.State = CheckState.Ok;
                PktmonCheck.After = " returned Not running";
                return true;
            }

            // A session is running. If it's ours (we're mid-capture) that's fine.
            if (S.Session.IsActive && S.Session.State != SessionState.External)
            {
                PktmonCheck.State = CheckState.Ok;
                PktmonCheck.After = " shows PktmonGUI's own capture";
                return true;
            }
            S.Session.MarkExternal();
            PktmonCheck.State = CheckState.Fail;
            PktmonCheck.After = $" shows a session already running ({status.LogMode ?? "unknown mode"}{(status.LogFile != null ? ", " + Path.GetFileName(status.LogFile) : "")}). " +
                                "Only one can run at a time; it may belong to another admin or a crashed PktmonGUI.";
            PktmonCheck.ActionText = "Stop it";
            PktmonCheck.Action = new AsyncRelayCommand(async () =>
            {
                if (!Ui.Confirm("Stop the running pktmon session?",
                        "Someone else's capture will end, and its .etl is kept wherever it was being written.\n\n" + status.Raw,
                        "Stop session", danger: true)) return;
                await S.Session.StopAsync("stopped from PktmonGUI preflight");
                await RunChecksAsync();
            });
            return true;
        }

        /// <summary>
        /// A real-time ETW session survives the process that started it. If PktmonGUI crashed or was
        /// killed mid-capture, its attribution session is still collecting; stop it.
        /// </summary>
        private void StopLeftoverEtwSession()
        {
            if (S.Session.IsActive) return; // ours, in use
            foreach (var name in SystemChecks.StopLeftoverEtwSessions())
                S.Log.Note($"Stopped the leftover ETW session {name} from an earlier PktmonGUI that didn't close cleanly");
        }

        /// <summary>
        /// Where the live settings are, whether a settings.json beside the exe was imported, and, when it
        /// wasn't because another account could have written it, the choice to review or ignore it.
        /// </summary>
        private void CheckSettings()
        {
            var store = S.Store;
            var st = S.Settings;
            var pending = store.PendingTemplate;
            SettingsCheck.Before = "In use: ";
            SettingsCheck.Mono = store.SettingsPath;
            SettingsCheck.ActionText = "Open folder";
            SettingsCheck.Action = new RelayCommand(() =>
                Ui.OpenInExplorer(File.Exists(store.SettingsPath) ? store.SettingsPath : store.DataFolder, select: File.Exists(store.SettingsPath)));
            SettingsCheck.Action2Text = null;
            SettingsCheck.Action2 = null;
            SettingsCheck.Action3Text = "Export…";
            SettingsCheck.Action3 = new RelayCommand(ExportTemplate);

            if (pending == null)
            {
                SettingsCheck.State = CheckState.Ok;
                SettingsCheck.After =
                    store.Template != null && (store.Template.Hash == null || store.Template.Hash != st.ImportedHash) ? $" · {store.TemplatePath} is ignored"
                    : st.ImportedFrom != null ? $" · imported from {st.ImportedFrom} on {st.ImportedAt:g}"
                    : " · no settings.json beside the exe";
                return;
            }

            SettingsCheck.State = CheckState.Warn;
            SettingsCheck.After = " · the settings.json beside the exe wasn't loaded: " + (pending.Error ?? pending.Untrusted);
            if (pending.Error == null)
            {
                SettingsCheck.ActionText = "Review…";
                SettingsCheck.Action = new RelayCommand(() => ReviewTemplate(pending));
            }
            SettingsCheck.Action2Text = "Ignore";
            SettingsCheck.Action2 = new RelayCommand(() =>
            {
                store.Decline(pending);
                CheckSettings();
            });
        }

        /// <summary>
        /// An untrusted template is imported only after the user has seen what it would change: another
        /// account could have written it, and PktmonGUI runs elevated with these values.
        /// </summary>
        private void ReviewTemplate(SettingsTemplate template)
        {
            var changes = template.Diff(S.Settings);
            var detail = changes.Count == 0 ? "Nothing differs from the settings in use." : string.Join(Environment.NewLine, changes);
            if (!Ui.Confirm("Import settings from an unprotected file?",
                    template.Untrusted + " Another account could have put these values there. Import them only if you know where the file came from.",
                    "Import", danger: true, detail: detail))
                return;
            var applied = S.Store.Import(template);
            S.Log.Note($"Imported {applied.Count} setting{(applied.Count == 1 ? "" : "s")} from {template.Path} after review" +
                       (applied.Count > 0 ? ": " + string.Join("; ", applied) : ""));
            CheckSettings();
            CheckFolder();
            _main.RaiseStorageChanged();
            if (applied.Count > 0)
                Ui.Info("Settings imported", "The working folder applies when you continue; the other settings take effect the next time PktmonGUI starts.");
        }

        /// <summary>
        /// Saves the settings in use as a settings.json to ship beside the exe: preferences only, never this
        /// machine's adapters or filters. Beside this exe it's imported at the next start, if it's trusted.
        /// </summary>
        private void ExportTemplate()
        {
            Ui.RememberWindow();
            S.Store.Save();
            var path = Ui.SaveFile("Export settings", "Settings (settings.json)|settings.json|JSON (*.json)|*.json",
                SettingsTemplate.FileName, S.Store.ExeFolder);
            if (path == null) return;
            try { SettingsTemplate.Export(S.Settings, path); }
            catch (Exception ex) { Ui.Error("Export failed", ex); return; }
            S.Log.Note($"Exported the settings in use to {path}");
            Ui.Info("Settings exported",
                $"Saved to {path}. Put it beside PktmonGUI.exe to use it as a template: the window imports it when it starts, " +
                "and headless captures take their defaults from it. It's only trusted where no other account can change the file or its folder; " +
                "see \"Shipping settings with the exe\" in the Admin Guide.");
            CheckSettings();
        }

        private void CheckFolder()
        {
            var folder = S.WorkingFolder;
            FolderCheck.Before = "";
            FolderCheck.Mono = folder;
            FolderCheck.ActionText = "Change";
            FolderCheck.Action = new RelayCommand(ChangeFolder);
            if (!AppServices.IsSafeWorkingFolder(folder))
            {
                FolderCheck.State = CheckState.Fail;
                FolderCheck.After = " · inside the Windows folder: pktmon would drop its files there";
                return;
            }
            if (AppServices.IsDefaultWorkingFolder(folder))
            {
                var problem = AppServices.CheckDefaultWorkingFolder();
                if (problem != null)
                {
                    // Continue fixes it: the folder is renamed aside (kept) and made again.
                    FolderCheck.State = CheckState.Warn;
                    FolderCheck.After = " · " + problem + " It's set aside and made again when you continue.";
                    return;
                }
            }
            string exposure = AppServices.IsDefaultWorkingFolder(folder) ? null : SecureFolder.Exposure(folder, CurrentUser());
            string free = "";
            try
            {
                var drive = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(folder)));
                free = BytesConverter.Format(drive.AvailableFreeSpace) + " free";
                FolderCheck.State = drive.AvailableFreeSpace < 1L << 30 ? CheckState.Warn : CheckState.Ok;
            }
            catch { FolderCheck.State = CheckState.Warn; free = "free space unknown"; }
            if (exposure != null) FolderCheck.State = CheckState.Warn;
            FolderCheck.After = $" · {free}{(Directory.Exists(folder) ? "" : " · created when you continue")}" +
                                (exposure != null ? $" · {exposure}: captures hold every packet" : " · never System32, where pktmon would drop its temp files");
        }

        private static SecurityIdentifier CurrentUser()
        {
            try { using (var id = WindowsIdentity.GetCurrent()) return id.User; } catch { return null; }
        }

        private void ChangeFolder()
        {
            var picked = Ui.PickFolder("Working folder for pktmon (captures and temp files go here)", S.WorkingFolder);
            if (picked == null) return;
            if (!AppServices.IsSafeWorkingFolder(picked))
            {
                Ui.Error("Not that folder", "Pick a folder outside the Windows directory. pktmon drops PktMon.etl and temp files into its working folder.");
                return;
            }
            try { S.WorkingFolder = picked; }
            catch (Exception ex) { Ui.Error("Couldn't use that folder", ex); return; }
            CheckFolder();
            RaiseContinue();
        }

        private async Task CheckFiltersAsync()
        {
            FiltersCheck.Action = null; FiltersCheck.ActionText = null;
            MachineFilters mf;
            try { mf = await S.Filters.ReadAsync(); }
            catch (Exception ex)
            {
                FiltersCheck.State = CheckState.Warn;
                FiltersCheck.Title = "Machine filters";
                FiltersCheck.Before = "Couldn't read them: " + ex.Message;
                FiltersCheck.Mono = null; FiltersCheck.After = null;
                return;
            }

            if (mf.Count == 0)
            {
                FiltersCheck.State = CheckState.Ok;
                FiltersCheck.Title = "No filters on this machine";
                FiltersCheck.Before = "Without rules, a capture sees every packet on the adapter. Add rules in ";
                FiltersCheck.Mono = "Filters";
                FiltersCheck.After = " to narrow it.";
                return;
            }
            if (mf.AreOurs)
            {
                FiltersCheck.State = CheckState.Ok;
                FiltersCheck.Title = $"{mf.Count} filters from PktmonGUI";
                FiltersCheck.Before = "The machine still holds the rules this tool applied last time.";
                FiltersCheck.Mono = null; FiltersCheck.After = null;
                return;
            }

            FiltersCheck.State = CheckState.Warn;
            FiltersCheck.Title = $"{mf.Count} filter{(mf.Count == 1 ? "" : "s")} already on this machine";
            FiltersCheck.Before = "";
            FiltersCheck.Mono = mf.Owner;
            FiltersCheck.After = (mf.Owner == "Defender for Endpoint" ? " owns them. " : " ") +
                "pktmon filters are machine-wide and can only be cleared all at once, so PktmonGUI will snapshot this set before it clears it, and offer to restore it when you stop.";
            FiltersCheck.ActionText = "Review";
            FiltersCheck.Action = new RelayCommand(() => Views.SnapshotDialog.ShowReview(mf));
        }

        private void CheckUnrestoredSnapshots()
        {
            if (_restoreCheck != null) { Checks.Remove(_restoreCheck); _restoreCheck = null; }
            var pending = S.Snapshots.FindUnrestored();
            if (pending.Count == 0 || S.Snapshots.Active != null) return;

            var (path, snap) = (pending[0].Key, pending[0].Value);
            _restoreCheck = new CheckItem
            {
                State = CheckState.Warn,
                Title = "A previous session didn't restore its filters",
                Before = $"On {snap.Taken:g} PktmonGUI cleared {snap.Rules.Count + snap.UnparsedLines.Count} filters from {snap.Owner} and never put them back (crash or forced close). Saved in ",
                Mono = Path.GetFileName(path),
                After = ".",
                ActionText = "Restore now",
                Action2Text = "Dismiss",
            };
            _restoreCheck.Action = new AsyncRelayCommand(async () =>
            {
                var current = S.Filters.Current;
                if (current.Count > 0 && !current.AreOurs &&
                    !Ui.Confirm("Replace the current filters?", $"Restoring clears the {current.Count} filters on the machine now and puts back the {snap.Rules.Count} from the snapshot.", "Restore", danger: true))
                    return;
                var failures = await S.Snapshots.RestoreAsync(snap, path);
                if (failures.Count > 0) Ui.Error("Some filters couldn't be restored", "Add these back by hand:", string.Join(Environment.NewLine, failures));
                await RunChecksAsync();
            });
            _restoreCheck.Action2 = new RelayCommand(() =>
            {
                if (!Ui.Confirm("Forget this snapshot?", "It stays on disk, but PktmonGUI won't offer to restore it again.", "Forget")) return;
                S.Snapshots.Dismiss(path, snap);
                Checks.Remove(_restoreCheck);
                _restoreCheck = null;
                RaiseContinue();
            });
            Checks.Add(_restoreCheck);
        }

        private async Task LoadAdaptersAsync()
        {
            AdapterError = null;
            List<Component> list;
            try { list = await S.Components.LoadAsync(ShowAllComponents); }
            catch (Exception ex)
            {
                AdapterError = "pktmon list failed: " + ex.Message;
                return;
            }

            var remembered = S.Settings.LastAdapterMacs ?? new List<string>();
            var previouslySelected = new HashSet<int>(Adapters.Where(a => a.IsSelected).Select(a => a.Id));
            foreach (var a in Adapters) a.PropertyChanged -= OnAdapterChanged;
            Adapters.Clear();

            var defaults = new HashSet<int>(previouslySelected.Count > 0
                ? previouslySelected
                : S.Components.PickDefaults(remembered).Select(c => c.Id));

            var ordered = list.OrderByDescending(c => c.IsAdapter)
                              .ThenByDescending(c => c.LinkStatus == "Up")
                              .ThenBy(c => c.IsWireless)
                              .ThenBy(c => c.Group)
                              .ThenBy(c => c.Id);
            foreach (var c in ordered)
            {
                var item = new AdapterItem(c) { IsSelected = defaults.Contains(c.Id) };
                item.PropertyChanged += OnAdapterChanged;
                Adapters.Add(item);
            }
            if (Adapters.Count == 0) AdapterError = "pktmon listed no network adapters.";
            RaiseContinue();
            _main.Capture.OnAdaptersChanged();
        }

        private void OnAdapterChanged(object sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName != nameof(AdapterItem.IsSelected)) return;
            RaiseContinue();
            _main.Capture.OnAdaptersChanged();
        }

        public IEnumerable<Component> SelectedComponents => Adapters.Where(a => a.IsSelected).Select(a => a.Component);

        [RelayCommand(CanExecute = nameof(CanContinue))]
        private void Continue()
        {
            var folderError = S.EnsureWorkingFolder(out var setAside);
            if (folderError != null)
            {
                Ui.Error("Working folder", folderError);
                CheckFolder();
                RaiseContinue();
                return;
            }
            if (setAside != null) Ui.Info("Working folder made again", setAside);
            S.Settings.LastAdapterMacs = SelectedComponents.Where(c => c.MacAddress != null).Select(c => c.MacAddress).ToList();
            S.Store.Save();
            _main.Capture.OnAdaptersChanged();
            _main.CurrentPage = Page.Capture;
        }

        [RelayCommand]
        private void CopyLog() => Ui.CopyText(S.Log.ToClipboardText());
    }
}
