using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PktmonGUI.Model;
using PktmonGUI.Parsing;
using PktmonGUI.Pktmon;
using PktmonGUI.Services;
using PktmonGUI.Util;
using Component = PktmonGUI.Model.Component;

namespace PktmonGUI.ViewModels
{
    public sealed class TargetOption
    {
        public string Label { get; set; }
        public string Detail { get; set; }
        public List<int> ComponentIds { get; set; } = new List<int>();
        public bool AllNics { get; set; }
        public List<Component> Components { get; set; } = new List<Component>();
        public bool IsWireless => Components.Any(c => c.IsWireless);
        public override string ToString() => Label;
    }

    public sealed partial class CaptureViewModel : ObservableObject
    {
        private readonly MainViewModel _main;
        private AppServices S => _main.Services;
        private readonly DispatcherTimer _pump;
        private RuleMatcher _matcher;

        public CaptureViewModel(MainViewModel main)
        {
            _main = main;
            var st = main.Services.Settings;
            Packets = new RingBufferCollection<PacketRecord>(Math.Max(1000, st.LiveRowCap));
            PacketsView = CollectionViewSource.GetDefaultView(Packets);
            InitColumnFilters();
            _fullPacket = st.FullPacket;
            _snapLength = st.SnapLength.ToString(CultureInfo.InvariantCulture);
            _autoScroll = st.AutoScroll;
            _attributeProcesses = st.AttributeProcesses;
            _saveLivePcap = st.SaveLivePcap;
            _mode = st.LastMode;
            _recordSizeMb = st.RecordFileSizeMb.ToString(CultureInfo.InvariantCulture);
            _recordLogMode = st.RecordLogMode;
            _rowCap = st.LiveRowCap.ToString(CultureInfo.InvariantCulture);
            _recordFileName = NewFileName();

            _pump = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(150) };
            _pump.Tick += (s, e) => Pump();

            S.Session.StateChanged += (s, e) => Ui.Post(OnSessionStateChanged);
            S.Session.UnexpectedExit += (s, msg) => Ui.Post(() =>
            {
                Banner = msg;
                BannerIsError = true;
                _ = AfterStopAsync(null);
            });
        }

        public RingBufferCollection<PacketRecord> Packets { get; }

        /// <summary>
        /// Events from the extra ETW providers set in Advanced. pktmon decodes them and prints them
        /// beside the packets; they are kept apart from the grid because they describe the stack,
        /// not a frame on the wire. Empty unless a provider was asked for.
        /// </summary>
        public RingBufferCollection<EtwEventRecord> Events { get; } = new RingBufferCollection<EtwEventRecord>(20000);
        public ICollectionView PacketsView { get; }
        public ObservableCollection<TargetOption> Targets { get; } = new ObservableCollection<TargetOption>();
        public ObservableCollection<RuleTally> Tallies { get; } = new ObservableCollection<RuleTally>();
        public CommandLog Log => S.Log;

        public static IReadOnlyList<LogMode> LogModes { get; } = new[] { LogMode.Circular, LogMode.MultiFile, LogMode.Memory };
        public static IReadOnlyList<PacketType> PacketTypes { get; } = new[] { PacketType.All, PacketType.Flow, PacketType.Drop };

        [ObservableProperty] private CaptureMode _mode;
        [ObservableProperty] private TargetOption _selectedTarget;
        [ObservableProperty] private bool _fullPacket;
        [ObservableProperty] private string _snapLength;
        [ObservableProperty] private string _recordFileName;
        [ObservableProperty] private string _recordSizeMb;
        [ObservableProperty] private LogMode _recordLogMode;
        [ObservableProperty] private PacketType _packetType = PacketType.Flow;
        [ObservableProperty] private string _flags;
        [ObservableProperty] private string _providersText;
        [ObservableProperty] private bool _showAdvanced;
        [ObservableProperty] private string _rowCap;

        [ObservableProperty] private bool _autoScroll;
        [ObservableProperty] private string _findText;
        [ObservableProperty] private PacketRecord _selectedPacket;
        [ObservableProperty] private bool _showRaw;

        [ObservableProperty] private long _matched;
        [ObservableProperty] private long _rx;
        [ObservableProperty] private long _tx;
        [ObservableProperty] private long _dropped;
        [ObservableProperty] private string _elapsed = "00:00:00";
        [ObservableProperty] private string _banner;
        [ObservableProperty] private bool _bannerIsError;
        /// <summary>The banner reports something that worked (e.g. the pcapng was saved).</summary>
        [ObservableProperty] private bool _bannerIsSuccess;

        partial void OnBannerChanged(string value) { if (value == null) BannerIsSuccess = false; }
        [ObservableProperty] private string _loadingText;

        // TCP handshake bookkeeping for the Counters page.
        [ObservableProperty] private long _synCount;
        [ObservableProperty] private long _synAckCount;

        /// <summary>Raised after new rows land, so the view can scroll to the end.</summary>
        public event EventHandler RowsAdded;

        public bool IsRunning => S.Session.IsActive && S.Session.State != SessionState.External;
        public bool IsBusy => S.Session.State == SessionState.Starting || S.Session.State == SessionState.Stopping || LoadingText != null;
        public bool IsIdle => !IsRunning && !IsBusy;
        public bool IsLive => Mode == CaptureMode.Live;
        public bool IsRecord => Mode == CaptureMode.Record;
        public bool IsCountersOnly => Mode == CaptureMode.CountersOnly;
        public string StartText => Mode == CaptureMode.Record ? "Record" : Mode == CaptureMode.CountersOnly ? "Count" : "Start";
        public long Discarded => Packets.Discarded;

        /// <summary>The events panel appears only once a provider has actually produced something.</summary>
        public bool HasEvents => Events.Count > 0;
        public string EventsText => Events.Discarded > 0
            ? $"{Events.Count:N0} events · {Events.Discarded:N0} older dropped"
            : $"{Events.Count:N0} events";
        public string RowsText
        {
            get
            {
                var total = Packets.Discarded > 0
                    ? $"{Packets.Count:N0} rows · {Packets.Discarded:N0} older rows dropped (cap {Packets.Capacity:N0})"
                    : $"{Packets.Count:N0} rows";
                // With a filter on, say how many of them are showing.
                return PacketsView?.Filter != null && PacketsView is ListCollectionView v ? $"{v.Count:N0} of {total}" : total;
            }
        }

        public string ModeHint
        {
            get
            {
                switch (Mode)
                {
                    case CaptureMode.Live: return SaveLivePcap
                        ? "Live: packets stream into the grid and are saved as pcapng."
                        : "Live: packets stream into the grid.";
                    case CaptureMode.Record: return "Record: writes an .etl file; packets load into the grid after Stop.";
                    default: return "Counters only: per-component totals, no packets stored.";
                }
            }
        }

        /// <summary>The detail behind <see cref="ModeHint"/>, shown in its tooltip.</summary>
        public string ModeHintDetail
        {
            get
            {
                switch (Mode)
                {
                    case CaptureMode.Live: return SaveLivePcap
                        ? "pktmon streams packets as text, and Save pcapng writes their real bytes to a .pcapng for Wireshark. pktmon also drops its own PktMon.etl in the working folder (512 MB, pre-allocated)."
                        : "pktmon streams packets as text. It still drops a PktMon.etl in the working folder (512 MB, pre-allocated) that Files can convert; tick Save pcapng for a file Wireshark opens as-is.";
                    case CaptureMode.Record: return "Writes an .etl in the working folder with live counters while it runs. After Stop, the packets load into the grid, and Files converts the .etl for Wireshark.";
                    default: return "Nothing is written to disk and there are no packets to inspect. Use it to answer \"is this traffic arriving at all?\"";
                }
            }
        }

        public string RulesSummary
        {
            get
            {
                var rules = _main.Filters?.CurrentRules().ToList() ?? new List<FilterRule>();
                if (rules.Count == 0) return "no rules";
                return rules.Count == 1 ? "1 rule" : rules.Count + " rules";
            }
        }

        public string RulesDetail
        {
            get
            {
                var rules = _main.Filters?.CurrentRules().ToList() ?? new List<FilterRule>();
                if (rules.Count == 0) return "every packet";
                var s = string.Join(" · ", rules.Take(4).Select(r => r.ShortLabel));
                return rules.Count > 4 ? s + " · …" : s;
            }
        }

        public bool RulesNotApplied => _main.Filters != null && _main.Filters.IsDirty;

        public string SelectedTargetText => SelectedTarget?.Label;

        public string PacketSizeArg => FullPacket ? "--pkt-size 0" : "--pkt-size " + (SnapLength ?? "128");

        partial void OnModeChanged(CaptureMode value)
        {
            OnPropertyChanged(nameof(IsLive));
            OnPropertyChanged(nameof(IsRecord));
            OnPropertyChanged(nameof(IsCountersOnly));
            OnPropertyChanged(nameof(StartText));
            OnPropertyChanged(nameof(ModeHint));
            OnPropertyChanged(nameof(ModeHintDetail));
            OnPropertyChanged(nameof(MultiFileSizeWarning));
            S.Settings.LastMode = value;
        }

        partial void OnSelectedTargetChanged(TargetOption value)
        {
            OnPropertyChanged(nameof(SelectedTargetText));
            _main.RefreshSessionCard();
        }

        partial void OnFullPacketChanged(bool value) { S.Settings.FullPacket = value; OnPropertyChanged(nameof(PacketSizeArg)); }
        partial void OnSnapLengthChanged(string value)
        {
            if (int.TryParse(value, out var n) && n > 0) S.Settings.SnapLength = n;
            OnPropertyChanged(nameof(PacketSizeArg));
        }
        partial void OnAutoScrollChanged(bool value) => S.Settings.AutoScroll = value;
        partial void OnRecordLogModeChanged(LogMode value)
        {
            S.Settings.RecordLogMode = value;
            OnPropertyChanged(nameof(MultiFileSizeWarning));
        }
        partial void OnRecordSizeMbChanged(string value)
        {
            if (int.TryParse(value, out var n) && n > 0) S.Settings.RecordFileSizeMb = n;
            OnPropertyChanged(nameof(MultiFileSizeWarning));
        }

        /// <summary>
        /// pktmon logs through 16 MB ETW buffers and starts the next multi-file part only after the
        /// queued buffers are written, so under load each part lands at a few hundred MB whatever the cap.
        /// </summary>
        public string MultiFileSizeWarning =>
            IsRecord && RecordLogMode == LogMode.MultiFile && int.TryParse(RecordSizeMb, out var mb) && mb > 0 && mb < 200
                ? $"pktmon can't split multi-file logs this finely: expect files of several hundred MB each, not {mb} MB."
                : null;
        partial void OnRowCapChanged(string value)
        {
            if (int.TryParse(value, NumberStyles.AllowThousands, CultureInfo.CurrentCulture, out var n) && n >= 1000)
            {
                S.Settings.LiveRowCap = n;
                Packets.Capacity = n;
                OnPropertyChanged(nameof(RowsText));
            }
        }

        partial void OnFindTextChanged(string value) => ApplyViewFilter();

        // ---- Column sorting and filtering ---------------------------------------------------

        /// <summary>One filter box per column, shown in the column headers.</summary>
        public IReadOnlyList<ColumnFilter> ColumnFilters { get; private set; }
        public ColumnFilter FilterFor(string key) => ColumnFilters.First(f => f.Key == key);

        public bool HasFilters => !string.IsNullOrWhiteSpace(FindText) || ColumnFilters.Any(f => f.IsActive);

        /// <summary>The sorted column, or null for capture order (# ascending).</summary>
        public string SortColumn { get; private set; }
        public ListSortDirection SortDirection { get; private set; }

        /// <summary>New rows go to the bottom only in capture order; that's when following them makes sense.</summary>
        public bool IsCaptureOrder => SortColumn == null || (SortColumn == PacketColumns.Number && SortDirection == ListSortDirection.Ascending);

        private void InitColumnFilters()
        {
            ColumnFilters = PacketColumns.All.Select(k => new ColumnFilter(k)).ToList();
            foreach (var f in ColumnFilters)
                f.PropertyChanged += (s, e) => { if (e.PropertyName == nameof(ColumnFilter.Text)) ApplyViewFilter(); };
        }

        private void ApplyViewFilter()
        {
            var tests = new List<Func<PacketRecord, bool>>();
            var q = FindText?.Trim();
            if (!string.IsNullOrEmpty(q)) tests.Add(p => MatchesFind(p, q));
            foreach (var f in ColumnFilters)
            {
                var t = PacketFilter.Compile(f.Key, f.Text);
                if (t != null) tests.Add(t);
            }
            PacketsView.Filter = tests.Count == 0 ? null : new Predicate<object>(o =>
            {
                var p = (PacketRecord)o;
                foreach (var t in tests) if (!t(p)) return false;
                return true;
            });
            OnPropertyChanged(nameof(HasFilters));
            OnPropertyChanged(nameof(RowsText));
        }

        /// <summary>
        /// Header click: ascending, then descending, then back to capture order. Returns the new direction
        /// (null = unsorted) so the view can draw the arrow.
        /// </summary>
        public ListSortDirection? SortBy(string column)
        {
            ListSortDirection? next;
            if (SortColumn != column) next = ListSortDirection.Ascending;
            else if (SortDirection == ListSortDirection.Ascending) next = ListSortDirection.Descending;
            else next = null;

            var view = (ListCollectionView)PacketsView;
            if (next == null)
            {
                SortColumn = null;
                view.CustomSort = null;
            }
            else
            {
                SortColumn = column;
                SortDirection = next.Value;
                view.CustomSort = new PacketComparer(column, next.Value);
            }
            OnPropertyChanged(nameof(IsCaptureOrder));
            return next;
        }

        [RelayCommand]
        private void ClearFilters()
        {
            FindText = null;
            foreach (var f in ColumnFilters) f.Text = null;
        }

        /// <summary>
        /// Free text matches any column including the process; <c>pid:1234</c> and <c>proc:chrome</c>
        /// match only the process, or the process a Dnscache DNS packet was for. This filters the
        /// display; pktmon itself can't filter by process.
        /// </summary>
        internal static bool MatchesFind(PacketRecord p, string q)
        {
            var a = p.Attribution;
            if (q.StartsWith("pid:", StringComparison.OrdinalIgnoreCase))
                return int.TryParse(q.Substring(4).Trim(), out var pid) && (a?.Pid == pid || a?.RequesterPid == pid);
            if (q.StartsWith("proc:", StringComparison.OrdinalIgnoreCase))
            {
                var name = q.Substring(5).Trim();
                return name.Length > 0 && a != null &&
                       ((a.Name ?? "").IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        (a.Services ?? "").IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        (a.Path ?? "").IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        (a.RequesterName ?? "").IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        (a.RequesterPath ?? "").IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
            }
            bool Has(string s) => s != null && s.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0;
            return Has(p.Protocol) || Has(p.Source) || Has(p.Destination) || Has(p.SrcIp) || Has(p.DstIp) ||
                   Has(p.Info) || Has(p.SrcMac) || Has(p.DstMac) || Has(p.DirText) || Has(p.DropReason) ||
                   Has(a?.Name) || Has(a?.Services) || Has(a?.RequesterName);
        }

        // ---- Process attribution ------------------------------------------------------

        [ObservableProperty] private bool _attributeProcesses;
        [ObservableProperty] private string _attributionText;
        [ObservableProperty] private string _attributionTooltip;
        [ObservableProperty] private bool _attributionWarning;

        partial void OnAttributeProcessesChanged(bool value) => S.Settings.AttributeProcesses = value;

        // ---- Live capture saved as pcapng ------------------------------------------------

        [ObservableProperty] private bool _saveLivePcap;
        [ObservableProperty] private string _lastPcapPath;

        partial void OnSaveLivePcapChanged(bool value)
        {
            S.Settings.SaveLivePcap = value;
            OnPropertyChanged(nameof(ModeHint));
            OnPropertyChanged(nameof(ModeHintDetail));
        }

        public bool CanOpenInWireshark => LastPcapPath != null && S.Wireshark != null;
        partial void OnLastPcapPathChanged(string value) => OnPropertyChanged(nameof(CanOpenInWireshark));

        [RelayCommand]
        private void OpenLastPcap()
        {
            if (LastPcapPath == null || S.Wireshark == null) return;
            try
            {
                // Medium integrity, via Explorer: Wireshark must not inherit our admin token (see ShellRun).
                if (ShellRun.TryOpen(S.Wireshark.WiresharkExe, PktmonCommand.QuoteArg(LastPcapPath)))
                    S.Log.Note("Opened in Wireshark: " + LastPcapPath);
                else
                    Ui.Info("Couldn't start Wireshark", $"Open it yourself and load:\n{LastPcapPath}");
            }
            catch (Exception ex) { Ui.Error("Couldn't start Wireshark", ex); }
        }

        [RelayCommand]
        private void ShowLastPcap()
        {
            if (LastPcapPath != null) Ui.OpenInExplorer(LastPcapPath, select: true);
        }

        private void UpdateAttributionStats(Attribution.AttributionEngine engine)
        {
            if (engine == null) { AttributionText = null; return; }
            var s = engine.Stats;
            var share = s.AttributedShare;
            AttributionText = share == null ? "Processes …" : $"Processes {share.Value:P0}";
            AttributionWarning = s.EtwError != null || s.EtwLost > 0;
            AttributionTooltip =
                $"{s.Resolved:N0} packets attributed to a process, {s.Unknown:N0} not found, {s.Pending:N0} waiting for their ETW event.\n" +
                $"{s.NoProcess:N0} have no local process (ARP, ICMP, forwarded traffic…) and aren't counted.\n" +
                (s.EtwError != null ? "ETW session failed: " + s.EtwError + ". Using the connection table only.\n"
                                    : $"ETW events: {s.EtwEvents:N0}" + (s.EtwLost > 0 ? $", {s.EtwLost:N0} LOST (buffers overflowed)" : "") + "\n") +
                "Matches packets to sockets per flow, from Kernel-Network events and the connection table.\n" +
                "DNS sent by the DNS Client service also names the process that asked, from DNS-Client events.";
        }

        [RelayCommand]
        private void ShowOnlyProcess()
        {
            var pid = SelectedPacket?.Attribution?.Pid;
            if (pid != null) FindText = "pid:" + pid;
        }

        [RelayCommand]
        private void CopyProcessPath()
        {
            var a = SelectedPacket?.Attribution;
            if (a?.Pid != null) Ui.CopyText(a.Path ?? a.Name);
        }

        partial void OnSelectedPacketChanged(PacketRecord value)
        {
            // Decode before the detail pane binds, so the title the decoder sets is ready.
            if (value != null) { var _ = value.Sections; }
            OnPropertyChanged(nameof(SelectedTitle));
        }

        public string SelectedTitle => SelectedPacket == null ? null : SelectedPacket.Title ?? $"{SelectedPacket.Protocol} · {SelectedPacket.Info}";

        // ---- Targets ----------------------------------------------------------------

        /// <summary>
        /// What Preflight had ticked the last time this list was built, so a choice made in the
        /// Adapter box itself survives a rebuild that didn't come from ticking something.
        /// </summary>
        private List<int> _targetsFrom;

        internal void OnAdaptersChanged()
        {
            var previous = SelectedTarget;
            Targets.Clear();
            var selected = _main.Preflight.SelectedComponents.ToList();
            var ids = selected.Select(c => c.Id).ToList();
            // pktmon monitors several components in one session (pktmon start --comp 15 20), so a
            // multi-adapter tick is a real target, not a mistake.
            if (selected.Count > 1)
                Targets.Add(new TargetOption
                {
                    Label = $"{selected.Count} components selected in Preflight",
                    Detail = "--comp " + string.Join(" ", ids),
                    ComponentIds = ids.ToList(),
                    Components = selected,
                });
            foreach (var a in _main.Preflight.Adapters)
                Targets.Add(new TargetOption
                {
                    Label = $"{a.Component.Name} · {a.Component.MacAddress ?? a.Component.Type} · id {a.Component.Id}",
                    Detail = "--comp " + a.Component.Id,
                    ComponentIds = new List<int> { a.Component.Id },
                    Components = new List<Component> { a.Component },
                });
            Targets.Add(new TargetOption { Label = "All network adapters (--comp nics)", Detail = "--comp nics", AllNics = true });

            // Ticking an adapter in Preflight must move this box; anything else leaves it alone.
            bool preflightChanged = _targetsFrom == null || !_targetsFrom.SequenceEqual(ids);
            SelectedTarget =
                (preflightChanged ? null : Targets.FirstOrDefault(t => previous != null && t.Label == previous.Label))
                ?? TargetFor(selected)
                ?? Targets.FirstOrDefault();
            _targetsFrom = ids;
        }

        /// <summary>
        /// The option that matches what Preflight has ticked: the combined one for several, that
        /// adapter's for one. With nothing ticked it falls back to Ethernet — the adapter most
        /// captures want — then to the adapter Preflight itself would have defaulted to (the one
        /// holding the default gateway), then to any wired adapter.
        /// </summary>
        private TargetOption TargetFor(List<Component> selected)
        {
            if (selected.Count > 1) return Targets.FirstOrDefault(t => t.ComponentIds.SequenceEqual(selected.Select(c => c.Id)));
            if (selected.Count == 1) return Targets.FirstOrDefault(t => t.ComponentIds.SequenceEqual(new[] { selected[0].Id }));

            bool NamedEthernet(Component c) =>
                c.ConnectionName != null && c.ConnectionName.StartsWith("Ethernet", StringComparison.OrdinalIgnoreCase);

            return Single(c => string.Equals(c.ConnectionName, "Ethernet", StringComparison.OrdinalIgnoreCase))
                ?? Single(NamedEthernet)
                ?? Single(c => c.Id == Preferred()?.Id)
                ?? Single(c => c.IsAdapter && !c.IsWireless && c.LinkStatus == "Up")
                ?? Targets.FirstOrDefault(t => t.Components.Count == 1);
        }

        /// <summary>The adapter Preflight would tick by itself: last used, else the default gateway's.</summary>
        private Component Preferred()
        {
            try { return S.Components.PickDefaults(S.Settings.LastAdapterMacs ?? new List<string>()).FirstOrDefault(); }
            catch { return null; }
        }

        private TargetOption Single(Func<Component, bool> match) =>
            Targets.FirstOrDefault(t => t.Components.Count == 1 && match(t.Components[0]));

        internal void OnRulesChanged()
        {
            OnPropertyChanged(nameof(RulesSummary));
            OnPropertyChanged(nameof(RulesDetail));
            OnPropertyChanged(nameof(RulesNotApplied));
        }

        // ---- Start / stop -------------------------------------------------------------

        private static string NewFileName() => $"capture-{DateTime.Now:yyyyMMdd-HHmmss}.etl";

        private CaptureOptions BuildOptions(List<string> errors)
        {
            var o = new CaptureOptions
            {
                Mode = Mode,
                AllNics = SelectedTarget?.AllNics == true,
                ComponentIds = SelectedTarget?.AllNics == true ? new List<int>() : SelectedTarget?.ComponentIds.ToList() ?? new List<int>(),
                Type = PacketType,
                Flags = string.IsNullOrWhiteSpace(Flags) ? null : Flags.Trim(),
            };
            if (FullPacket) o.PacketSize = 0;
            else if (int.TryParse(SnapLength, out var snap) && snap > 0) o.PacketSize = snap;
            else errors.Add("Snap length must be a positive number of bytes (or tick Full packet).");

            if (Mode == CaptureMode.Record)
            {
                var name = (RecordFileName ?? "").Trim();
                if (name.Length == 0) name = NewFileName();
                if (!name.EndsWith(".etl", StringComparison.OrdinalIgnoreCase)) name += ".etl";
                if (name.IndexOfAny(Path.GetInvalidPathChars()) >= 0) errors.Add("The file name has invalid characters.");
                else o.FileName = Path.IsPathRooted(name) ? name : Path.Combine(S.WorkingFolder, name);
                if (int.TryParse(RecordSizeMb, out var mb) && mb > 0) o.FileSizeMb = mb;
                else errors.Add("File size must be a positive number of MB.");
                o.LogMode = RecordLogMode;
            }

            foreach (var line in (ProvidersText ?? "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                // "Microsoft-Windows-TCPIP [0xFF] [4]"
                var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) continue;
                var p = new EtwProvider { Name = parts[0] };
                if (parts.Length > 1) p.Keywords = parts[1];
                if (parts.Length > 2 && int.TryParse(parts[2], out var lvl)) p.Level = lvl;
                o.Providers.Add(p);
            }
            errors.AddRange(o.Validate());
            return o;
        }

        public string StartPreview
        {
            get
            {
                var o = BuildOptions(new List<string>());
                return PktmonCommand.Start(o).DisplayText;
            }
        }

        [RelayCommand]
        private async Task StartStopAsync()
        {
            if (IsRunning) await StopAsync();
            else await StartAsync();
        }

        private async Task StartAsync()
        {
            if (IsBusy) return;
            Banner = null; BannerIsError = false;
            var errors = new List<string>();
            var options = BuildOptions(errors);
            if (errors.Count > 0) { Ui.Error("Can't start yet", string.Join("\n", errors)); return; }

            // Filters: pktmon reads them at start, so the draft must be applied first.
            var filters = _main.Filters;
            if (filters.AnyInvalid) { Ui.Error("Fix the filter rules", "One of the rules on the Filters page has an error."); _main.CurrentPage = Page.Filters; return; }
            var machine = S.Filters.Current;
            if (filters.IsDirty)
            {
                var n = filters.RuleCount;
                var answer = Ui.Ask("Apply your filter rules first?",
                    n == 0 ? $"Your draft has no rules, but the machine has {machine.Count}. Start with the machine's filters as they are?"
                           : $"Your {n} rule(s) aren't on the machine yet. pktmon reads its filters when the capture starts.",
                    n == 0 ? "Keep machine filters" : "Apply and start", n == 0 ? "Cancel" : "Start without them");
                if (answer == Views.DialogResultKind.Cancel || answer == Views.DialogResultKind.None) return;
                if (n > 0 && answer == Views.DialogResultKind.Yes)
                {
                    await filters.ApplyCommand.ExecuteAsync(null);
                    if (filters.IsDirty) return; // apply was cancelled or failed
                }
                if (n == 0 && answer == Views.DialogResultKind.No) return;
            }
            else if (machine.HasForeign && filters.RuleCount == 0)
            {
                // Someone else's rules (e.g. Defender for Endpoint) would silently decide what this capture sees.
                if (!Ui.Confirm("Capture through someone else's filters?",
                        $"The machine has {machine.Count} filters from {machine.Owner}. pktmon applies them to every capture, so you'll only see packets they match.\n\n" +
                        "To capture everything instead, go to Filters and use Remove all from machine (they're snapshotted and put back when PktmonGUI closes).",
                        "Start anyway"))
                    return;
            }

            if (options.Mode == CaptureMode.Record && File.Exists(options.FileName) &&
                !Ui.Confirm("Overwrite?", $"{Path.GetFileName(options.FileName)} exists in the working folder. pktmon will overwrite it.", "Overwrite", danger: true))
                return;

            if (SelectedTarget?.IsWireless == true && options.Mode == CaptureMode.Record)
                Banner = "Wireless adapter: pktmon records Wi-Fi traffic, but converting it with etl2pcap may not give a file Wireshark reads cleanly.";

            ClearRows();
            var ruleSet = (S.Filters.Current.AreOurs ? S.Settings.AppliedRules : S.Filters.Current.Filters.Select(f => f.Rule)).ToList();
            _matcher = new RuleMatcher(ruleSet);
            Tallies.Clear();
            foreach (var r in ruleSet) Tallies.Add(new RuleTally(r));

            try
            {
                var comps = SelectedTarget?.Components ?? new List<Component>();
                LastPcapPath = null;
                await S.Session.StartAsync(options, S.Components.All, ruleSet, AttributeProcesses,
                    saveLivePcap: SaveLivePcap, livePcapMaxBytes: (long)Math.Max(16, S.Settings.LivePcapMaxMb) << 20);
                _pump.Start();
                S.Counters.Start(); // per-component counters in every mode
                if (options.Mode == CaptureMode.CountersOnly) _main.CurrentPage = Page.Counters;
            }
            catch (Exception ex)
            {
                _pump.Stop();
                S.Counters.Stop();
                Ui.Error("pktmon didn't start", ex.Message);
            }
            finally
            {
                if (options.Mode == CaptureMode.Record) RecordFileName = NewFileName();
                RaiseState();
            }
        }

        private async Task StopAsync()
        {
            if (!IsRunning) return;
            string etl = null;
            try { etl = await S.Session.StopAsync(); }
            catch (Exception ex) { Ui.Error("Stopping failed", ex); }
            await AfterStopAsync(etl);
        }

        private async Task AfterStopAsync(string etl)
        {
            S.Counters.Stop();
            Pump();
            _pump.Stop();
            RaiseState();
            if (etl != null && File.Exists(etl))
                await LoadEtlAsync(etl);
            else if (etl != null)
            {
                // Multi-file: pktmon wrote name1.etl, name2.etl… instead of name.etl. Load the newest parts,
                // up to a default single file's 512 MB, so loading takes no longer than a circular capture.
                var parts = CaptureFiles.PartsOf(etl);
                var load = CaptureFiles.NewestParts(parts, 512L << 20);
                if (load.Count > 0)
                {
                    await LoadEtlAsync(load);
                    if (load.Count < parts.Count && !BannerIsError)
                    {
                        var note = $"Multi-file capture: the grid shows its last {load.Count} of {parts.Count} files " +
                                   $"({Path.GetFileName(load[0])}{(load.Count > 1 ? " to " + Path.GetFileName(load[load.Count - 1]) : "")}). All of them are on the Files page.";
                        Banner = Banner == null ? note : note + "\n" + Banner;
                    }
                }
            }

            var pcap = S.Session.LastLivePcap;
            if (pcap != null)
            {
                bool usable = pcap.Packets > 0 && File.Exists(pcap.Path);
                LastPcapPath = usable ? pcap.Path : null;
                var saved = usable ? "Saved " + pcap.Summary : "Nothing saved as pcapng: " + (pcap.Error ?? "no packets arrived from the PktMon provider");
                // Keep an unexpected-exit message in front if there is one.
                Banner = BannerIsError && Banner != null ? Banner + "\n" + saved : saved;
                BannerIsError = BannerIsError || pcap.Error != null;
                BannerIsSuccess = usable && !BannerIsError;
            }
            _main.Files.Refresh();
        }

        /// <summary>Record mode: convert the .etl with etl2txt and load the packets into the grid.</summary>
        public Task LoadEtlAsync(string etl) => LoadEtlAsync(new[] { etl });

        /// <summary>Loads one capture's .etl files (several for multi-file parts, oldest first) into the grid.</summary>
        public async Task LoadEtlAsync(IReadOnlyList<string> etls)
        {
            if (etls.Count == 0) return;
            LoadingText = $"Loading {(etls.Count == 1 ? Path.GetFileName(etls[0]) : etls.Count + " files")} (pktmon etl2txt)…";
            RaiseState();
            var txt = Path.Combine(Path.GetTempPath(), "pktmongui-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                int cap = Packets.Capacity;
                ClearRows();
                // Processes come from the flow table recorded beside the .etl, if there is one.
                Attribution.AttributionEngine offline = null;
                var sidecar = CaptureFiles.AttributionPathFor(etls[0]);
                if (File.Exists(sidecar))
                {
                    try { offline = Attribution.AttributionEngine.FromSnapshot(Json.Load<Attribution.AttributionSnapshot>(sidecar)); }
                    catch (Exception ex) { Banner = "Couldn't read the process attribution file: " + ex.Message; }
                }
                // Stream the text: a full 512 MB .etl becomes gigabytes of text, so only the newest `cap` rows are kept.
                var keep = new Queue<PacketRecord>(Math.Min(cap, 100_000));
                // Extra providers recorded into the .etl come back out of etl2txt beside the
                // packets; keep the newest, the same way the packets are kept.
                var events = new Queue<EtwEventRecord>();
                long total = 0;
                foreach (var etl in etls)
                {
                    var r = await S.Runner.RunAsync(PktmonCommand.Etl2Txt(etl, txt, verbose: false));
                    if (!r.Success || !File.Exists(txt))
                    {
                        Banner = $"etl2txt failed{(etls.Count > 1 ? " on " + Path.GetFileName(etl) : "")}: " + r.Output;
                        BannerIsError = true;
                        return;
                    }
                    total += await Task.Run(() =>
                    {
                        long count = 0;
                        var parser = new RealtimeParser();
                        using (var reader = OutputDecoder.OpenFile(txt))
                        {
                            void Take(IEnumerable<PacketRecord> ps)
                            {
                                foreach (var p in ps)
                                {
                                    count++;
                                    keep.Enqueue(p);
                                    if (keep.Count > cap) keep.Dequeue();
                                }
                            }
                            string line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                Take(parser.Feed(line));
                                if (parser.LastLineKind != RealtimeParser.LineKind.Event) continue;
                                events.Enqueue(parser.LastEvent);
                                if (events.Count > Events.Capacity) events.Dequeue();
                            }
                            Take(parser.Flush());
                        }
                        return count;
                    });
                    try { File.Delete(txt); } catch { }
                }
                var window = keep.ToList();
                if (offline != null) await Task.Run(() => { foreach (var p in window) offline.Observe(p); });
                UpdateAttributionStats(offline);
                foreach (var p in window) Count(p);
                Packets.AddRange(window);
                if (events.Count > 0)
                {
                    Events.AddRange(events.ToList());
                    OnPropertyChanged(nameof(EventsText));
                    OnPropertyChanged(nameof(HasEvents));
                }
                if (total > window.Count) Banner = $"{total:N0} packets in the file{(etls.Count > 1 ? "s" : "")}; the grid shows the last {window.Count:N0}. Files → Convert for the whole capture in Wireshark.";
                OnPropertyChanged(nameof(RowsText));
                if (etls.Count == 1)
                {
                    // A multi-file part has no meta.json of its own, so the capture's count isn't overwritten.
                    var metaPath = CaptureSession.MetaPathFor(etls[0]);
                    var meta = Json.Load<CaptureMeta>(metaPath);
                    if (meta != null) { meta.Packets = total; Json.Save(metaPath, meta); }
                }
            }
            catch (Exception ex) { Banner = "Couldn't load the capture: " + ex.Message; BannerIsError = true; }
            finally
            {
                try { File.Delete(txt); } catch { }
                LoadingText = null;
                RaiseState();
            }
        }

        private void OnSessionStateChanged() => RaiseState();

        // What the empty grid says: in Record and Counters-only mode no packets arrive while running.
        public string EmptyTitle =>
            !IsRunning ? "No packets yet."
            : Mode == CaptureMode.Record ? "Recording…"
            : Mode == CaptureMode.CountersOnly ? "Counting packets…"
            : "Waiting for packets…";
        public string EmptyHint =>
            !IsRunning ? "Pick an adapter, check the rules, and press Start."
            : Mode == CaptureMode.Record ? $"Packets are written to {Path.GetFileName(S.Session.Meta?.EtlFile) ?? "the .etl file"} and load into the grid after Stop."
            : Mode == CaptureMode.CountersOnly ? "Counters-only mode keeps no packets. The totals are on the Counters page."
            : "None has matched the rules yet.";

        private void RaiseState()
        {
            OnPropertyChanged(nameof(IsRunning));
            OnPropertyChanged(nameof(IsBusy));
            OnPropertyChanged(nameof(IsIdle));
            OnPropertyChanged(nameof(EmptyTitle));
            OnPropertyChanged(nameof(EmptyHint));
            _main.Filters?.ApplyCommand.NotifyCanExecuteChanged();
            _main.Counters?.OnSessionChanged();
        }

        // ---- Pump -----------------------------------------------------------------

        private void Pump()
        {
            var q = S.Session.Incoming;
            if (!q.IsEmpty)
            {
                var batch = new List<PacketRecord>(Math.Min(q.Count, 5000));
                while (batch.Count < 5000 && q.TryDequeue(out var p))
                {
                    Count(p);
                    batch.Add(p);
                }
                Packets.AddRange(batch);
                OnPropertyChanged(nameof(RowsText));
                foreach (var t in Tallies) t.Notify();
                if (AutoScroll && IsCaptureOrder) RowsAdded?.Invoke(this, EventArgs.Empty);
            }

            var eq = S.Session.IncomingEvents;
            if (!eq.IsEmpty)
            {
                var batch = new List<EtwEventRecord>(Math.Min(eq.Count, 5000));
                while (batch.Count < 5000 && eq.TryDequeue(out var ev)) batch.Add(ev);
                bool first = Events.Count == 0;
                Events.AddRange(batch);
                OnPropertyChanged(nameof(EventsText));
                if (first) OnPropertyChanged(nameof(HasEvents));
            }

            string info = null;
            while (S.Session.InfoLines.TryDequeue(out var line))
                if (!IsBoilerplate(line)) info = line.Trim();
            if (info != null && IsRunning) { Banner = "pktmon: " + info; BannerIsError = info.IndexOf("fail", StringComparison.OrdinalIgnoreCase) >= 0 || info.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0; }

            var engine = S.Session.Attribution;
            if (engine != null)
            {
                // Packets logged before their ETW event get their process now (the row repaints itself).
                engine.TakeBackfilled();
                UpdateAttributionStats(engine);
            }

            var e = S.Session.Elapsed;
            Elapsed = $"{(int)e.TotalHours:00}:{e.Minutes:00}:{e.Seconds:00}";
        }

        private static bool IsBoilerplate(string line)
        {
            var t = line.Trim();
            if (t.Length == 0) return true;
            // The start banner (same sections as `pktmon status`) and the stop message.
            return t.EndsWith(":", StringComparison.Ordinal) || t == "Processing..." || t == "None" ||
                   t.StartsWith("Packet counters", StringComparison.Ordinal) || t == "All packets" || t == "Flow packets" || t == "Drop packets" ||
                   t == "Network adapters" || t == "Counters" || t.StartsWith("Logger name", StringComparison.Ordinal) ||
                   t.StartsWith("Logging mode", StringComparison.Ordinal) || t.StartsWith("Log file", StringComparison.Ordinal) ||
                   t.StartsWith("Max file size", StringComparison.Ordinal) || t.StartsWith("Memory used", StringComparison.Ordinal) ||
                   t.StartsWith("Events lost", StringComparison.Ordinal) || t.StartsWith("Component", StringComparison.Ordinal) ||
                   t.StartsWith("ID ", StringComparison.Ordinal) || t.StartsWith("--", StringComparison.Ordinal) ||
                   t.StartsWith("Microsoft-Windows-PktMon", StringComparison.Ordinal) ||
                   // pktmon stop ends a real-time session by pulling the driver out from under it.
                   t.IndexOf("does not recognize the command", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void Count(PacketRecord p)
        {
            Matched++;
            if (p.IsDrop) { Dropped++; return; }
            if (p.Direction == Direction.Rx) Rx++;
            else if (p.Direction == Direction.Tx) Tx++;

            if (_matcher != null && Tallies.Count > 0)
            {
                int i = _matcher.Match(p);
                if (i >= 0 && i < Tallies.Count)
                {
                    var t = Tallies[i];
                    if (p.Direction == Direction.Rx) { t.RxPackets++; t.RxBytes += p.Length; }
                    else { t.TxPackets++; t.TxBytes += p.Length; }
                }
            }

            if (p.Protocol == "TCP" && p.TcpFlags.HasFlag(TcpFlags.SYN))
            {
                if (p.TcpFlags.HasFlag(TcpFlags.ACK)) SynAckCount++;
                else SynCount++;
            }
        }

        private void ClearRows()
        {
            Packets.Clear();
            Events.Clear();
            SelectedPacket = null;
            Matched = Rx = Tx = Dropped = SynCount = SynAckCount = 0;
            foreach (var t in Tallies) { t.RxPackets = t.TxPackets = t.RxBytes = t.TxBytes = 0; t.Notify(); }
            OnPropertyChanged(nameof(RowsText));
            OnPropertyChanged(nameof(EventsText));
            OnPropertyChanged(nameof(HasEvents));
        }

        [RelayCommand]
        private void Clear()
        {
            ClearRows();
            Banner = null;
        }

        [RelayCommand]
        private void SaveRows()
        {
            if (Packets.Count == 0) { Ui.Info("Nothing to save", "The grid is empty."); return; }
            var path = Ui.SaveFile("Save rows as text", "Text (*.txt)|*.txt", $"pktmon-{DateTime.Now:yyyyMMdd-HHmmss}.txt", S.WorkingFolder);
            if (path == null) return;
            try
            {
                using (var w = new StreamWriter(path, false, new UTF8Encoding(false)))
                    foreach (var p in Packets)
                        foreach (var l in p.RawLines) w.WriteLine(l);
            }
            catch (Exception ex) { Ui.Error("Couldn't save", ex); }
        }

        [RelayCommand]
        private void CopyPacket()
        {
            if (SelectedPacket != null) Ui.CopyText(SelectedPacket.RawText);
        }

        [RelayCommand]
        private void CopyLog() => Ui.CopyText(S.Log.ToClipboardText());

        [RelayCommand]
        private void GoToFilters() => _main.CurrentPage = Page.Filters;

        [RelayCommand]
        private void SetMode(CaptureMode mode) { if (!IsRunning) Mode = mode; }

        internal void OnShutdown()
        {
            _pump.Stop();
        }
    }
}
