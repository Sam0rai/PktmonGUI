using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PktmonGUI.Model;
using PktmonGUI.Pktmon;
using PktmonGUI.Services;

namespace PktmonGUI.ViewModels
{
    public enum CounterView { Flow, Drop, All }

    public sealed class CounterRowVm
    {
        public CounterRowVm(CounterRow r, bool inScope) { Row = r; InScope = inScope; }
        public CounterRow Row { get; }
        public bool InScope { get; }
        public int Id => Row.ComponentId;
        public string Name => Row.ComponentName;
        public string Group => string.IsNullOrEmpty(Row.Group) || Row.Group == Row.ComponentName ? "" : Row.Group;
        public long RxPackets => Row.RxPackets;
        public long RxBytes => Row.RxBytes;
        public long TxPackets => Row.TxPackets;
        public long TxBytes => Row.TxBytes;
        public long RxDrops => Row.RxDropPackets;
        public long TxDrops => Row.TxDropPackets;
        public string DropReason => Row.DropReasonText;
        public string DropSources => string.Join(", ", Row.DropSources.Distinct());
        public string Split
        {
            get
            {
                long total = Row.RxPackets + Row.TxPackets;
                if (total == 0) return "";
                int rx = (int)Math.Round(100.0 * Row.RxPackets / total);
                return $"{rx}% in / {100 - rx}% out";
            }
        }
    }

    public sealed partial class CountersViewModel : ObservableObject
    {
        private readonly MainViewModel _main;
        private AppServices S => _main.Services;
        private IReadOnlyList<CounterRow> _last = new CounterRow[0];
        private readonly DispatcherTimer _ageTimer;
        private readonly Queue<(DateTime t, long total)> _history = new Queue<(DateTime, long)>();

        public CountersViewModel(MainViewModel main)
        {
            _main = main;
            _refreshSeconds = main.Services.Settings.CountersRefreshSeconds;
            S.Counters.Updated += (s, rows) => Ui.Post(() => OnCounters(rows));
            S.Counters.Failed += (s, msg) => Ui.Post(() => Error = msg);
            _ageTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            _ageTimer.Tick += (s, e) => OnPropertyChanged(nameof(UpdatedText));
            _ageTimer.Start();
            BuildPreview();
        }

        public ObservableCollection<CounterRowVm> Rows { get; } = new ObservableCollection<CounterRowVm>();
        public ObservableCollection<CommandPreview> Preview { get; } = new ObservableCollection<CommandPreview>();
        public ObservableCollection<RuleTally> Tallies => _main.Capture.Tallies;

        public static IReadOnlyList<int> RefreshChoices { get; } = new[] { 1, 2, 5, 10 };

        [ObservableProperty] private int _refreshSeconds;
        [ObservableProperty] private CounterView _view = CounterView.Flow;
        [ObservableProperty] private bool _showZero;
        [ObservableProperty] private bool _showAllComponents;
        [ObservableProperty] private string _error;

        [ObservableProperty] private long _totalPackets;
        [ObservableProperty] private long _rxPackets;
        [ObservableProperty] private long _rxBytes;
        [ObservableProperty] private long _txPackets;
        [ObservableProperty] private long _txBytes;
        [ObservableProperty] private long _drops;
        [ObservableProperty] private string _rate;

        public bool IsRunning => S.Session.IsActive && S.Session.State != SessionState.External;
        public bool IsCountersOnly => IsRunning && S.Session.Options?.Mode == CaptureMode.CountersOnly;
        public bool IsLive => IsRunning && S.Session.Options?.Mode == CaptureMode.Live;
        public bool ShowRuleTable => IsLive && Tallies.Count > 0;
        public bool ShowDrops => View != CounterView.Flow;
        public bool ShowFlows => View != CounterView.Drop;

        public string RxShare => TotalPackets == 0 ? "" : $"{Math.Round(100.0 * RxPackets / TotalPackets)}% of matched";
        public string TxShare => TotalPackets == 0 ? "" : $"{Math.Round(100.0 * TxPackets / TotalPackets)}% of matched";

        public string HandshakeText
        {
            get
            {
                var c = _main.Capture;
                return c.SynCount == 0 && c.SynAckCount == 0 ? "—" : $"{c.SynCount:N0} → {c.SynAckCount:N0}";
            }
        }

        public string HandshakeNote
        {
            get
            {
                var c = _main.Capture;
                if (!IsLive) return "SYN vs SYN,ACK, live mode only";
                if (c.SynCount == 0) return "no SYNs seen yet";
                long missing = c.SynCount - c.SynAckCount;
                // Outbound SYNs and inbound SYN,ACKs pair up only when we're the client; show the raw gap.
                return missing > 0 ? $"{missing:N0} SYNs got no SYN,ACK back" : "every SYN was answered";
            }
        }

        public string ScopeText
        {
            get
            {
                var o = S.Session.Options;
                if (o == null) return _main.Capture.SelectedTargetText ?? "";
                return o.AllNics ? "Scope: all network adapters" :
                    "Scope: component " + string.Join(", ", o.ComponentIds.Select(id => id + " · " + (S.Components.All.FirstOrDefault(c => c.Id == id)?.Name ?? "?")));
            }
        }

        public string UpdatedText
        {
            get
            {
                if (!IsRunning) return S.Counters.LastUpdate == null ? "Not polling: start a capture" : "Stopped";
                var last = S.Counters.LastUpdate;
                if (last == null) return "Waiting for the first poll…";
                var age = DateTime.Now - last.Value;
                return $"Updated {age.TotalSeconds:0.0} s ago";
            }
        }

        public string DropSummary
        {
            get
            {
                if (Drops == 0) return "Nothing is being discarded by the stack on the captured components.";
                var worst = Rows.Where(r => r.InScope || ShowAllComponents).OrderByDescending(r => r.RxDrops + r.TxDrops).FirstOrDefault();
                return worst == null ? $"{Drops:N0} packets dropped."
                    : $"{Drops:N0} packets dropped. Most at {worst.Name}" + (string.IsNullOrEmpty(worst.DropReason) ? "." : $": {worst.DropReason}.");
            }
        }

        partial void OnRefreshSecondsChanged(int value)
        {
            S.Counters.IntervalSeconds = value;
            S.Settings.CountersRefreshSeconds = value;
            BuildPreview();
        }

        partial void OnViewChanged(CounterView value)
        {
            OnPropertyChanged(nameof(ShowDrops));
            OnPropertyChanged(nameof(ShowFlows));
            BuildPreview();
            Rebuild();
        }

        partial void OnShowZeroChanged(bool value) { BuildPreview(); Rebuild(); }
        partial void OnShowAllComponentsChanged(bool value) { BuildPreview(); Rebuild(); }

        internal void OnSessionChanged()
        {
            OnPropertyChanged(nameof(IsRunning));
            OnPropertyChanged(nameof(IsCountersOnly));
            OnPropertyChanged(nameof(IsLive));
            OnPropertyChanged(nameof(ShowRuleTable));
            OnPropertyChanged(nameof(ScopeText));
            OnPropertyChanged(nameof(UpdatedText));
            if (S.Session.State == SessionState.Starting) { _history.Clear(); Error = null; }
            BuildPreview();
        }

        private void OnCounters(IReadOnlyList<CounterRow> rows)
        {
            _last = rows;
            Error = null;
            Rebuild();
            OnPropertyChanged(nameof(UpdatedText));
            OnPropertyChanged(nameof(HandshakeText));
            OnPropertyChanged(nameof(HandshakeNote));
            OnPropertyChanged(nameof(ShowRuleTable));
        }

        private void Rebuild()
        {
            var o = S.Session.Options;
            var scope = o == null || o.AllNics ? null : new HashSet<int>(o.ComponentIds);
            bool InScope(CounterRow r) => scope == null ? S.Components.All.Any(c => c.Id == r.ComponentId && c.IsAdapter) || o?.AllNics == true : scope.Contains(r.ComponentId);

            var visible = _last.Select(r => new CounterRowVm(r, InScope(r)))
                .Where(r => ShowAllComponents || r.InScope)
                .Where(r => ShowZero || (View == CounterView.Drop ? r.RxDrops + r.TxDrops > 0 : r.RxPackets + r.TxPackets + r.RxDrops + r.TxDrops > 0))
                .OrderByDescending(r => r.InScope)
                .ThenByDescending(r => View == CounterView.Drop ? r.RxDrops + r.TxDrops : r.RxPackets + r.TxPackets)
                .ToList();

            Rows.Clear();
            foreach (var r in visible) Rows.Add(r);

            var inScope = _last.Where(InScope).ToList();
            RxPackets = inScope.Sum(r => r.RxPackets);
            TxPackets = inScope.Sum(r => r.TxPackets);
            RxBytes = inScope.Sum(r => r.RxBytes);
            TxBytes = inScope.Sum(r => r.TxBytes);
            TotalPackets = RxPackets + TxPackets;
            Drops = inScope.Sum(r => r.RxDropPackets + r.TxDropPackets);

            var now = DateTime.Now;
            _history.Enqueue((now, TotalPackets));
            while (_history.Count > 0 && (now - _history.Peek().t).TotalSeconds > 60) _history.Dequeue();
            var first = _history.Peek();
            double secs = (now - first.t).TotalSeconds;
            Rate = secs >= 1 ? $"last {secs:0} s · {(TotalPackets - first.total) / secs:0}/s now" : "";

            OnPropertyChanged(nameof(RxShare));
            OnPropertyChanged(nameof(TxShare));
            OnPropertyChanged(nameof(DropSummary));
        }

        private void BuildPreview()
        {
            Preview.Clear();
            var o = S.Session.Options;
            if (o != null && IsRunning)
                Preview.Add(new CommandPreview(PktmonCommand.Start(o).DisplayText,
                    o.Mode == CaptureMode.CountersOnly ? "-o keeps it to counters only" : null));
            Preview.Add(new CommandPreview(CountersPoller.Command.DisplayText, $"polled every {RefreshSeconds} s, the equivalent of --live --refresh-rate"));
            var console = PktmonCommand.Counters(View == CounterView.All ? null : View.ToString().ToLowerInvariant(),
                includeHidden: ShowAllComponents, zero: ShowZero, dropReason: View != CounterView.Flow);
            Preview.Add(new CommandPreview(console.DisplayText + " --live", "the same view at a prompt"));
            Preview.Add(new CommandPreview("pktmon stop", "closing PktmonGUI also stops it"));
        }

        [RelayCommand]
        private async Task ResetAsync()
        {
            if (!IsRunning) return;
            var r = await S.Runner.RunAsync(PktmonCommand.Reset());
            if (!r.Success) { Ui.Error("Reset failed", r.Output); return; }
            _history.Clear();
            await S.Counters.PollNowAsync();
        }

        [RelayCommand]
        private async Task StopAsync()
        {
            if (!IsRunning) return;
            await _main.Capture.StartStopCommand.ExecuteAsync(null);
        }

        [RelayCommand]
        private void SwitchToCapture()
        {
            _main.Capture.Mode = CaptureMode.Live;
            _main.CurrentPage = Page.Capture;
        }

        [RelayCommand]
        private void CopyPreview() => Ui.CopyText(string.Join(Environment.NewLine, Preview.Select(p => p.Text)));
    }
}
