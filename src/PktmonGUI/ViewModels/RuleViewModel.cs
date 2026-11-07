using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PktmonGUI.Model;

namespace PktmonGUI.ViewModels
{
    public sealed class RuleChip
    {
        public RuleChip(string label, string value) { Label = label; Value = value; }
        public string Label { get; }
        public string Value { get; }
    }

    /// <summary>How a rule in the list compares with the machine's filters.</summary>
    public enum RuleStatus
    {
        /// <summary>Not on the machine: Apply adds it.</summary>
        New,
        /// <summary>On the machine exactly as listed.</summary>
        Applied,
        /// <summary>Edited since it went on the machine: Apply replaces the old version.</summary>
        Changed,
    }

    /// <summary>One editable rule card. Text fields are kept as strings so half-typed input can be shown with its error.</summary>
    public sealed partial class RuleViewModel : ObservableObject
    {
        private readonly FiltersViewModel _owner;

        public RuleViewModel(FiltersViewModel owner, FilterRule rule, bool editing = false)
        {
            _owner = owner;
            Load(rule);
            _isEditing = editing;
        }

        [ObservableProperty] private int _index;
        [ObservableProperty] private bool _isEditing;
        [ObservableProperty] private bool _showAdvanced;

        [ObservableProperty] private string _name;
        [ObservableProperty] private string _ip1;
        [ObservableProperty] private string _ip2;
        [ObservableProperty] private string _transport;
        [ObservableProperty] private string _port1;
        [ObservableProperty] private string _port2;
        [ObservableProperty] private string _mac1;
        [ObservableProperty] private string _mac2;
        [ObservableProperty] private string _etherType;
        [ObservableProperty] private string _vlan;
        [ObservableProperty] private string _dscp;
        [ObservableProperty] private bool _heartbeat;
        [ObservableProperty] private bool _encap;
        [ObservableProperty] private string _encapPort;

        [ObservableProperty] private bool _syn;
        [ObservableProperty] private bool _ack;
        [ObservableProperty] private bool _fin;
        [ObservableProperty] private bool _rst;
        [ObservableProperty] private bool _psh;
        [ObservableProperty] private bool _urg;
        [ObservableProperty] private bool _ece;
        [ObservableProperty] private bool _cwr;

        /// <summary>Added by Add rule or Duplicate and not yet confirmed with Done: a duplicate is dropped rather than kept.</summary>
        internal bool IsNew { get; set; }

        [ObservableProperty] private RuleStatus _status;
        /// <summary>For a changed rule, the version on the machine, as <c>filter add</c> arguments.</summary>
        [ObservableProperty] private string _appliedAs;
        /// <summary>The match key of the machine filter this rule was last seen as, so an edit reads as Changed, not New.</summary>
        internal string OriginKey { get; set; }

        public string StatusLabel => Status switch
        {
            RuleStatus.Applied => "On machine",
            RuleStatus.Changed => "Changed",
            _ => "Not applied",
        };

        public string StatusTip => Status switch
        {
            RuleStatus.Applied => "This filter is on the machine exactly as shown.",
            RuleStatus.Changed => "Edited since it went on the machine. Apply to machine replaces the old version.",
            _ => "Not on the machine yet. Apply to machine adds it.",
        };

        partial void OnStatusChanged(RuleStatus value)
        {
            OnPropertyChanged(nameof(StatusLabel));
            OnPropertyChanged(nameof(StatusTip));
        }

        partial void OnIsEditingChanged(bool value)
        {
            if (!value) IsNew = false;
        }

        public static IReadOnlyList<string> TransportChoices { get; } = new[] { "Any", "TCP", "UDP", "ICMP", "ICMPv6" };
        public static IReadOnlyList<string> EtherTypeChoices { get; } = new[] { "Any" }.Concat(FilterRule.KnownEtherTypes.Select(k => k.Key)).ToList();

        public bool IsTcp => string.Equals(Transport, "TCP", StringComparison.OrdinalIgnoreCase) || Transport == "6";

        private void Load(FilterRule r)
        {
            _name = r.Name;
            _ip1 = r.Ip1; _ip2 = r.Ip2;
            _transport = r.Transport ?? "Any";
            _port1 = r.Port1?.ToString(CultureInfo.InvariantCulture);
            _port2 = r.Port2?.ToString(CultureInfo.InvariantCulture);
            _mac1 = r.Mac1; _mac2 = r.Mac2;
            _etherType = r.EtherType == null ? "Any"
                : FilterRule.KnownEtherTypes.FirstOrDefault(k => string.Equals(k.Value, r.EtherType, StringComparison.OrdinalIgnoreCase)).Key ?? r.EtherType;
            _vlan = r.Vlan?.ToString(CultureInfo.InvariantCulture);
            _dscp = r.Dscp?.ToString(CultureInfo.InvariantCulture);
            _heartbeat = r.Heartbeat;
            _encap = r.Encap;
            _encapPort = r.EncapPort?.ToString(CultureInfo.InvariantCulture);
            var f = r.TcpFlags;
            _syn = f.HasFlag(TcpFlags.SYN); _ack = f.HasFlag(TcpFlags.ACK); _fin = f.HasFlag(TcpFlags.FIN); _rst = f.HasFlag(TcpFlags.RST);
            _psh = f.HasFlag(TcpFlags.PSH); _urg = f.HasFlag(TcpFlags.URG); _ece = f.HasFlag(TcpFlags.ECE); _cwr = f.HasFlag(TcpFlags.CWR);
            _showAdvanced = r.Ip2 != null || r.Port2 != null || r.Mac2 != null || r.Dscp != null || r.Heartbeat || r.Encap;
        }

        /// <summary>The rule as typed. Unparseable numbers become a validation error rather than silently vanishing.</summary>
        public FilterRule ToRule(List<string> errors = null)
        {
            string S(string v) => string.IsNullOrWhiteSpace(v) ? null : v.Trim();
            int? N(string v, string label)
            {
                if (string.IsNullOrWhiteSpace(v)) return null;
                if (int.TryParse(v.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var n)) return n;
                errors?.Add(v.Contains("-") && label.StartsWith("Port") ? "Port ranges aren't supported by pktmon; add one rule per port." : $"{label} must be a number.");
                return null;
            }

            var r = new FilterRule
            {
                Name = S(Name),
                Ip1 = S(Ip1), Ip2 = S(Ip2),
                Transport = Transport == null || Transport == "Any" ? null : S(Transport),
                Port1 = N(Port1, "Port"), Port2 = N(Port2, "Second port"),
                Mac1 = S(Mac1), Mac2 = S(Mac2),
                Vlan = N(Vlan, "VLAN ID"), Dscp = N(Dscp, "DSCP"),
                Heartbeat = Heartbeat,
                Encap = Encap,
                EncapPort = Encap ? N(EncapPort, "VXLAN port") : null,
            };
            if (EtherType != null && EtherType != "Any")
            {
                var known = FilterRule.KnownEtherTypes.FirstOrDefault(k => k.Key == EtherType);
                r.EtherType = known.Value ?? EtherType.Trim();
            }
            if (r.Transport != null)
            {
                var known = FilterRule.KnownTransports.FirstOrDefault(t => string.Equals(t, r.Transport, StringComparison.OrdinalIgnoreCase));
                if (known != null) r.Transport = known;
            }
            if (r.IsTcp)
            {
                var f = TcpFlags.None;
                if (Syn) f |= TcpFlags.SYN; if (Ack) f |= TcpFlags.ACK; if (Fin) f |= TcpFlags.FIN; if (Rst) f |= TcpFlags.RST;
                if (Psh) f |= TcpFlags.PSH; if (Urg) f |= TcpFlags.URG; if (Ece) f |= TcpFlags.ECE; if (Cwr) f |= TcpFlags.CWR;
                r.TcpFlags = f;
            }
            return r;
        }

        public List<string> Errors
        {
            get
            {
                var errors = new List<string>();
                var r = ToRule(errors);
                errors.AddRange(r.Validate());
                if (r.Name != null && r.Name.Length > 64) errors.Add("Keep the name under 64 characters.");
                var dup = _owner?.FindDuplicate(this, earlierOnly: true);
                if (dup != null) errors.Add($"Same filter as rule {dup.Index}: it matches the same packets.");
                return errors.Distinct().ToList();
            }
        }

        /// <summary>Re-reads the errors after another rule changed (a duplicate depends on the whole list).</summary>
        internal void RefreshErrors()
        {
            OnPropertyChanged(nameof(Errors));
            OnPropertyChanged(nameof(IsValid));
            OnPropertyChanged(nameof(ErrorText));
        }

        public bool IsValid => Errors.Count == 0;
        public string ErrorText => string.Join("  ", Errors);

        public string Title => string.IsNullOrWhiteSpace(Name) ? "Rule " + Index : Name;
        public string Sentence => ToRule().Describe();
        public string CommandText => Pktmon.PktmonCommand.FilterAdd(ToRule()).DisplayText;
        public bool IsCatchAll => ToRule().IsEmpty;

        public List<RuleChip> Chips
        {
            get
            {
                var r = ToRule();
                var chips = new List<RuleChip>();
                if (r.Ip1 != null) chips.Add(new RuleChip("IP", r.Ip2 == null ? r.Ip1 : r.Ip1 + " ↔ " + r.Ip2));
                if (r.Mac1 != null) chips.Add(new RuleChip("MAC", r.Mac2 == null ? r.Mac1 : r.Mac1 + " ↔ " + r.Mac2));
                if (r.EtherType != null) chips.Add(new RuleChip("EtherType", EtherType));
                if (r.Vlan.HasValue) chips.Add(new RuleChip("VLAN", r.Vlan.ToString()));
                if (r.Dscp.HasValue) chips.Add(new RuleChip("DSCP", r.Dscp.ToString()));
                if (r.Transport != null) chips.Add(new RuleChip("Proto", r.Transport));
                if (r.IsTcp && r.TcpFlags != TcpFlags.None) chips.Add(new RuleChip("Flags", string.Join(" ", FilterRule.FlagList(r.TcpFlags))));
                if (r.Port1.HasValue) chips.Add(new RuleChip("Port", r.Port2 == null ? r.Port1.ToString() : r.Port1 + ", " + r.Port2));
                if (r.Heartbeat) chips.Add(new RuleChip("Heartbeat", "UDP 3343"));
                if (r.Encap) chips.Add(new RuleChip("Encap", r.EncapPort.HasValue ? "VXLAN " + r.EncapPort : "inner + outer"));
                return chips;
            }
        }

        public string EmptyNote => IsCatchAll
            ? "No field set, so every packet on the adapter matches this rule."
            : Chips.Count == 1 ? $"No other field set, so every {Chips[0].Value} packet on this adapter matches." : null;

        protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
        {
            base.OnPropertyChanged(e);
            switch (e.PropertyName)
            {
                case nameof(IsEditing):
                case nameof(ShowAdvanced):
                case nameof(Status):
                case nameof(StatusLabel):
                case nameof(StatusTip):
                case nameof(AppliedAs):
                case nameof(Errors):
                case nameof(IsValid):
                case nameof(ErrorText):
                case nameof(Title):
                case nameof(Sentence):
                case nameof(CommandText):
                case nameof(Chips):
                case nameof(EmptyNote):
                case nameof(IsTcp):
                case nameof(IsCatchAll):
                    return;
            }
            if (e.PropertyName == nameof(Transport)) OnPropertyChanged(nameof(IsTcp));
            OnPropertyChanged(nameof(Errors));
            OnPropertyChanged(nameof(IsValid));
            OnPropertyChanged(nameof(ErrorText));
            OnPropertyChanged(nameof(Title));
            OnPropertyChanged(nameof(Sentence));
            OnPropertyChanged(nameof(CommandText));
            OnPropertyChanged(nameof(Chips));
            OnPropertyChanged(nameof(EmptyNote));
            OnPropertyChanged(nameof(IsCatchAll));
            _owner?.OnRuleChanged();
        }

        [RelayCommand] private void Edit() { _owner.BeginEdit(this); }
        [RelayCommand] private void Done() => _owner.CommitEdit(this);
        [RelayCommand] private void Remove() => _owner.RemoveRule(this);
        [RelayCommand] private void MoveUp() => _owner.Move(this, -1);
        [RelayCommand] private void MoveDown() => _owner.Move(this, 1);
        [RelayCommand] private void Duplicate() => _owner.DuplicateRule(this);
    }
}
