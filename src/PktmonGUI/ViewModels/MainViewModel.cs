using System;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PktmonGUI.Model;
using PktmonGUI.Services;
using PktmonGUI.Util;

namespace PktmonGUI.ViewModels
{
    public enum Page { Preflight, Capture, Counters, Filters, Files }

    public sealed partial class MainViewModel : ObservableObject
    {
        public MainViewModel(AppServices services)
        {
            Services = services;
            Preflight = new PreflightViewModel(this);
            Filters = new FiltersViewModel(this);
            Capture = new CaptureViewModel(this);
            Counters = new CountersViewModel(this);
            Files = new FilesViewModel(this);
            Tour = new TourViewModel(this);
            _isSidebarCollapsed = services.Settings.SidebarCollapsed;
            _theme = ThemeManager.Mode;
            ThemeManager.Changed += (s, e) => OnPropertyChanged(nameof(IsLightTheme));

            services.Session.StateChanged += (s, e) => Ui.Post(RefreshSessionCard);
            services.Filters.Changed += (s, e) => Ui.Post(RefreshSessionCard);
            RefreshSessionCard();
        }

        public AppServices Services { get; }
        public PreflightViewModel Preflight { get; }
        public CaptureViewModel Capture { get; }
        public CountersViewModel Counters { get; }
        public FiltersViewModel Filters { get; }
        public FilesViewModel Files { get; }
        public TourViewModel Tour { get; }

        public string HostName => Environment.MachineName;
        public string Version => "v" + Assembly.GetExecutingAssembly().GetName().Version.ToString(3);
        public string StorageTooltip =>
            "Settings, presets and snapshots:\n" + Services.Store.DataFolder +
            (Services.Settings.ImportedFrom != null ? $"\nImported from {Services.Settings.ImportedFrom}, {Services.Settings.ImportedAt:g}" : "");

        /// <summary>After Preflight imports the template beside the exe.</summary>
        public void RaiseStorageChanged() => OnPropertyChanged(nameof(StorageTooltip));

        public bool IsAdministrator => SystemChecks.IsAdministrator();

        [ObservableProperty] private Page _currentPage = Page.Preflight;
        [ObservableProperty] private bool _isBusy;
        [ObservableProperty] private string _busyText;

        public bool IsPreflight => CurrentPage == Page.Preflight;

        partial void OnCurrentPageChanged(Page value)
        {
            OnPropertyChanged(nameof(IsPreflight));
            if (value == Page.Files) Files.Refresh();
            if (value == Page.Filters) _ = Filters.RefreshMachineAsync();
        }

        [RelayCommand]
        private void Navigate(Page page) => CurrentPage = page;

        /// <summary>Sidebar shows icons only (Ctrl+B).</summary>
        [ObservableProperty] private bool _isSidebarCollapsed;
        partial void OnIsSidebarCollapsedChanged(bool value) => Services.Settings.SidebarCollapsed = value;

        [RelayCommand]
        private void ToggleSidebar() => IsSidebarCollapsed = !IsSidebarCollapsed;

        /// <summary>Dark, Light, or following Windows' app mode (title bar button; right-click for all three).</summary>
        [ObservableProperty] private AppTheme _theme;
        partial void OnThemeChanged(AppTheme value)
        {
            Services.Settings.Theme = value;
            ThemeManager.Apply(value);
        }

        /// <summary>The palette actually showing, which for <see cref="AppTheme.System"/> depends on Windows.</summary>
        public bool IsLightTheme => ThemeManager.IsLight;

        /// <summary>Flips to the other palette (Ctrl+Shift+L); this leaves "Match Windows".</summary>
        [RelayCommand]
        private void ToggleTheme() => Theme = IsLightTheme ? AppTheme.Dark : AppTheme.Light;

        [RelayCommand]
        private void SetTheme(AppTheme theme)
        {
            // Clicking the checked item unchecks it in the menu; re-raise so the check comes back.
            if (Theme == theme) OnPropertyChanged(nameof(Theme));
            else Theme = theme;
        }

        public async Task InitializeAsync()
        {
            await Preflight.RunChecksAsync();
            // Offered once the checks are in, so its first stop shows real results.
            if (Services.Settings.ShowTourAtStartup && !Tour.IsOpen) Tour.Start(offer: true);
        }

        /// <summary>The title bar's ? button and F1.</summary>
        [RelayCommand]
        private void StartTour() => Tour.Start(offer: false);

        // ---- Sidebar session card ---------------------------------------------------

        [ObservableProperty] private string _sessionTitle = "Idle";
        [ObservableProperty] private string _sessionTone = "Idle";
        [ObservableProperty] private string _sessionLine1;
        [ObservableProperty] private string _sessionLine2;
        [ObservableProperty] private string _sessionLine3;
        [ObservableProperty] private string _filterNote;

        public void RefreshSessionCard()
        {
            var session = Services.Session;
            var o = session.Options;
            switch (session.State)
            {
                case SessionState.Running:
                    SessionTitle = o?.Mode == CaptureMode.CountersOnly ? "Counting" : o?.Mode == CaptureMode.Record ? "Recording" : "Capturing";
                    SessionTone = o?.Mode == CaptureMode.Record ? "Record" : "Running";
                    break;
                case SessionState.Starting: SessionTitle = "Starting…"; SessionTone = "Busy"; break;
                case SessionState.Stopping: SessionTitle = "Stopping…"; SessionTone = "Busy"; break;
                case SessionState.External: SessionTitle = "Running (not ours)"; SessionTone = "Warn"; break;
                default: SessionTitle = "Idle"; SessionTone = "Idle"; break;
            }

            if (session.IsActive && o != null)
            {
                var names = o.AllNics ? "all NICs" : string.Join(", ", o.ComponentIds.Select(id => Services.Components.All.FirstOrDefault(c => c.Id == id)?.Name ?? "id " + id));
                SessionLine1 = names;
                SessionLine2 = (o.AllNics ? "--comp nics" : "--comp " + string.Join(" ", o.ComponentIds)) + " · " +
                               (o.Mode == CaptureMode.Live ? "real-time" : o.Mode == CaptureMode.Record ? CaptureOptions.LogModeArg(o.LogMode) : "counters only");
                SessionLine3 = o.Mode == CaptureMode.Record
                                   ? $"{o.FileSizeMb ?? 512} MB {(o.LogMode == LogMode.MultiFile ? "requested per file" : "max")} → {System.IO.Path.GetFileName(o.FileName)}"
                             : o.Mode == CaptureMode.Live ? (o.PacketSize == 0 ? "--pkt-size 0 (full packets)" : $"--pkt-size {o.PacketSize ?? 128}") : "-o, nothing written to disk";
            }
            else if (session.State == SessionState.External)
            {
                SessionLine1 = "Started outside PktmonGUI";
                SessionLine2 = "Stop it from Preflight";
                SessionLine3 = null;
            }
            else
            {
                SessionLine1 = Capture?.SelectedTargetText;
                SessionLine2 = "Ready";
                SessionLine3 = null;
            }

            var mf = Services.Filters.Current;
            var snap = Services.Snapshots.Active;
            if (snap != null && !snap.Restored)
                FilterNote = $"Filters are machine-wide. {snap.Rules.Count + snap.UnparsedLines.Count} foreign filters are held in a snapshot" +
                             (snap.RestoreOnStop ? " and go back when PktmonGUI closes." : ".");
            else if (mf.HasForeign)
                FilterNote = $"Filters are machine-wide. {mf.Count} filters from {mf.Owner} are on this machine.";
            else if (mf.AreOurs)
                FilterNote = $"Filters are machine-wide. {mf.Count} rules from PktmonGUI are applied.";
            else
                FilterNote = "Filters are machine-wide. None are set, so every packet on the adapter is captured.";
        }

        /// <summary>Called by the window on close: always stop pktmon and restore foreign filters.</summary>
        public async Task ShutdownAsync()
        {
            IsBusy = true;
            BusyText = Services.Session.IsActive && Services.Session.State != SessionState.External
                ? "Stopping capture and restoring filters…"
                : "Restoring filters…";
            Capture.OnShutdown();
            Services.Settings.DraftRules = Filters.CurrentRules().ToList();
            await Services.ShutdownAsync();
        }

        public bool NeedsShutdownWork =>
            (Services.Session.IsActive && Services.Session.State != SessionState.External) ||
            Services.Snapshots.HasPendingRestore || Services.Filters.Current.AreOurs;
    }
}
