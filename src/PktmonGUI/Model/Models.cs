using System;
using System.Collections.Generic;
using System.Linq;

namespace PktmonGUI.Model
{
    /// <summary>A packet-processing component from <c>pktmon list</c>.</summary>
    public sealed class Component
    {
        public int Id { get; set; }
        public string Name { get; set; }
        /// <summary>Group heading in pktmon list, e.g. "Network Adapters", "vSwitches".</summary>
        public string Group { get; set; }
        /// <summary>Component type, e.g. "Miniport", "Filter", "Protocol", "HNS", "vSwitch".</summary>
        public string Type { get; set; }
        public string MacAddress { get; set; }
        public bool Hidden { get; set; }
        /// <summary>For filter/protocol components: the adapter ID they sit on.</summary>
        public int? ParentId { get; set; }
        public Dictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();

        // Enriched from System.Net.NetworkInformation by matching on MAC.
        public string IPv4 { get; set; }
        public string LinkStatus { get; set; }
        public long? LinkSpeedBps { get; set; }
        public bool IsWireless { get; set; }
        public string InterfaceDescription { get; set; }
        public string ConnectionName { get; set; }

        public bool IsAdapter =>
            MacAddress != null &&
            (Group?.IndexOf("adapter", StringComparison.OrdinalIgnoreCase) >= 0 ||
             string.Equals(Type, "Miniport", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(Type, "NetVsc", StringComparison.OrdinalIgnoreCase));

        public string LinkText
        {
            get
            {
                if (LinkStatus == null) return "";
                if (!string.Equals(LinkStatus, "Up", StringComparison.OrdinalIgnoreCase)) return LinkStatus == "Down" ? "Not connected" : LinkStatus;
                return LinkSpeedBps.HasValue && LinkSpeedBps > 0 ? FormatSpeed(LinkSpeedBps.Value) + " up" : "up";
            }
        }

        public static string FormatSpeed(long bps)
        {
            if (bps >= 1_000_000_000) return (bps / 1_000_000_000.0).ToString("0.#") + " Gbps";
            if (bps >= 1_000_000) return (bps / 1_000_000.0).ToString("0.#") + " Mbps";
            return (bps / 1000.0).ToString("0.#") + " Kbps";
        }

        public string Display => $"{Name} · {MacAddress ?? Type} · id {Id}";
        public override string ToString() => Display;
    }

    public enum Direction { Unknown, Rx, Tx }

    /// <summary>One packet as printed by pktmon (real-time or etl2txt).</summary>
    public sealed class PacketRecord : System.ComponentModel.INotifyPropertyChanged
    {
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        private Attribution.ProcessAttribution _attribution;
        /// <summary>
        /// The owning process. Changes after the row is shown (Pending → Resolved) when the ETW
        /// event arrives after the packet, so it's the one property that notifies.
        /// </summary>
        public Attribution.ProcessAttribution Attribution
        {
            get => _attribution;
            set
            {
                if (ReferenceEquals(_attribution, value)) return;
                _attribution = value;
                _sections = null; // the Process section in the decoder changes too
                PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(Attribution)));
                PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(ProcessText)));
                PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(Sections)));
            }
        }

        public string ProcessText => _attribution?.Text ?? "";

        // Sort keys for the Source/Destination columns, computed once (the grid re-sorts often).
        internal string SrcSortKey;
        internal string DstSortKey;

        public long Number { get; set; }
        public string Timestamp { get; set; }
        /// <summary>hh:mm:ss.fff for the grid; the full 100 ns timestamp is in the detail pane.</summary>
        public string TimeShort => ShortTime(Timestamp);

        /// <summary>Trims a 100 ns timestamp to milliseconds, for anything shown a row at a time.</summary>
        public static string ShortTime(string timestamp)
        {
            if (timestamp == null) return null;
            int dot = timestamp.IndexOf('.');
            return dot > 0 && timestamp.Length > dot + 4 ? timestamp.Substring(0, dot + 4) : timestamp;
        }
        public DateTime? Time { get; set; }
        public Direction Direction { get; set; }
        public string DirText => Direction == Direction.Rx ? "Inbound" : Direction == Direction.Tx ? "Outbound" : "";
        public int? ComponentId { get; set; }
        public int? FilterId { get; set; }
        public long? PktGroupId { get; set; }
        public int? PktNumber { get; set; }
        public int? Appearance { get; set; }
        public int? Edge { get; set; }
        public int? OriginalSize { get; set; }
        public int? LoggedSize { get; set; }
        public string MediaType { get; set; }
        public bool IsDrop { get; set; }
        public string DropReason { get; set; }
        public string DropLocation { get; set; }

        public string SrcMac { get; set; }
        public string DstMac { get; set; }
        public string EtherType { get; set; }
        public int? Vlan { get; set; }
        public string Source { get; set; }
        public string Destination { get; set; }
        public string SrcIp { get; set; }
        public string DstIp { get; set; }
        public int? SrcPort { get; set; }
        public int? DstPort { get; set; }
        /// <summary>DNS, TCP, UDP, ICMP, ARP, LLDP, CDP, ...</summary>
        public string Protocol { get; set; }
        /// <summary>IP protocol number if known.</summary>
        public int? IpProtocol { get; set; }
        /// <summary>
        /// A DNS packet's ID and question, for matching it to the process that asked. Read from the
        /// bytes for pcapng frames; for pktmon's text, parsed from <see cref="Info"/> when needed.
        /// </summary>
        public Attribution.DnsQuestion Dns { get; set; }
        public TcpFlags TcpFlags { get; set; }
        public string Info { get; set; }

        private string _title;
        /// <summary>Headline for the detail pane; written by the decoder, so reading it decodes first.</summary>
        public string Title
        {
            get { if (_sections == null && !_decoding) { var _ = Sections; } return _title; }
            set => _title = value;
        }

        /// <summary>The exact lines pktmon printed for this packet.</summary>
        public List<string> RawLines { get; set; } = new List<string>();
        public string Payload { get; set; }
        /// <summary>Verbose IP header summary (ttl, id, flags, flowlabel...) when pktmon printed one.</summary>
        public string IpHeader { get; set; }
        public bool Truncated { get; set; }

        // Filled lazily by the decoders when the row is selected.
        private List<DecodedSection> _sections;
        private List<SymbolLegend> _legend;
        private bool _decoding;
        public List<DecodedSection> Sections
        {
            get
            {
                if (_sections != null) return _sections;
                _decoding = true;
                try { return _sections = Parsing.Decoders.PacketDecoder.Decode(this, out _legend); }
                finally { _decoding = false; }
            }
        }
        public List<SymbolLegend> Legend { get { var _ = Sections; return _legend; } }

        public int Length => OriginalSize ?? LoggedSize ?? 0;
        public string RawText => string.Join(Environment.NewLine, RawLines);
    }

    /// <summary>
    /// One event from an extra ETW provider (Capture ▸ Advanced ▸ ETW providers, <c>pktmon --trace -p</c>).
    /// pktmon decodes these itself and prints them in the same stream as the packets, on the same
    /// clock, so they can be read against the packets: the stack's own account of a drop, a reset
    /// or a connection, which the packet capture can't give on its own.
    /// </summary>
    public sealed class EtwEventRecord
    {
        public long Number { get; set; }
        public string Timestamp { get; set; }
        public DateTime? Time { get; set; }
        public string TimeShort => PacketRecord.ShortTime(Timestamp);

        /// <summary>
        /// How pktmon labelled the event: <c>TCP</c>, <c>TCPIP</c>, <c>IP</c>, <c>UDP</c> in real-time
        /// output, or the provider name from etl2txt's <c>[Microsoft-Windows-TCPIP]</c>. Null when
        /// pktmon printed no label.
        /// </summary>
        public string Source { get; set; }
        public string Text { get; set; }
        /// <summary>The line exactly as pktmon printed it.</summary>
        public string Raw { get; set; }

        /// <summary>
        /// The event says something was dropped, refused or failed. These are the ones worth adding a
        /// provider for, so the panel marks them.
        /// </summary>
        public bool IsBad =>
            Has("dropped") || Has("Reason=") || Has("Reason =") || Has("failure") || Has("failed") ||
            Has("Action = Block") || Has("abort") || Has("reset");

        private bool Has(string s) => Text != null && Text.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0;

        public override string ToString() => Raw;
    }

    public sealed class DecodedSection
    {
        public DecodedSection(string name, params DecodedField[] fields) { Name = name; Fields = fields.ToList(); }
        public string Name { get; }
        public List<DecodedField> Fields { get; }
    }

    public enum FieldTone { Normal, Good, Warn, Bad }

    public sealed class DecodedField
    {
        public DecodedField(string key, string value, FieldTone tone = FieldTone.Normal) { Key = key; Value = value; Tone = tone; }
        public string Key { get; }
        public string Value { get; }
        public FieldTone Tone { get; }
    }

    public sealed class SymbolLegend
    {
        public SymbolLegend(string symbol, string meaning) { Symbol = symbol; Meaning = meaning; }
        public string Symbol { get; }
        public string Meaning { get; }
    }

    /// <summary>One component's counters from <c>pktmon counters --json</c>.</summary>
    public sealed class CounterRow
    {
        public int ComponentId { get; set; }
        public string ComponentName { get; set; }
        public string Group { get; set; }
        public int? Edge { get; set; }
        public string EdgeName { get; set; }
        public long RxPackets { get; set; }
        public long RxBytes { get; set; }
        public long TxPackets { get; set; }
        public long TxBytes { get; set; }
        public long RxDropPackets { get; set; }
        public long RxDropBytes { get; set; }
        public long TxDropPackets { get; set; }
        public long TxDropBytes { get; set; }
        public string RxDropReason { get; set; }
        public string TxDropReason { get; set; }
        public string RxDropLocation { get; set; }
        public string TxDropLocation { get; set; }
        /// <summary>Drivers that reported drops (e.g. "e1d68x64.sys").</summary>
        public List<string> DropSources { get; set; } = new List<string>();
        public string DropReasonText =>
            string.Join("; ", new[] { RxDropReason == null ? null : "Rx: " + RxDropReason, TxDropReason == null ? null : "Tx: " + TxDropReason }.Where(s => s != null));
        public long TotalPackets => RxPackets + TxPackets;
        public long TotalDrops => RxDropPackets + TxDropPackets;
    }

    /// <summary>A filter currently on the machine, read back from <c>pktmon filter list</c>.</summary>
    public sealed class ExistingFilter
    {
        public int Index { get; set; }
        public FilterRule Rule { get; set; }
        /// <summary>The raw text line(s), kept for display and in snapshots.</summary>
        public string RawText { get; set; }
        /// <summary>True when every column could be mapped back to a <c>filter add</c> argument.</summary>
        public bool FullyParsed { get; set; } = true;
    }

    public sealed class Preset
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public bool BuiltIn { get; set; }
        public List<FilterRule> Rules { get; set; } = new List<FilterRule>();

        public string Summary => Rules.Count == 1 ? Rules[0].ArgsSummary : $"{Rules.Count} rules";
    }

    /// <summary>
    /// The filter set that was on the machine before PktmonGUI cleared it.
    /// Written to snapshots\*.json before the clear, so it survives a crash.
    /// </summary>
    public sealed class FilterSnapshot
    {
        public DateTime Taken { get; set; }
        public string Machine { get; set; }
        public string Owner { get; set; }
        public bool RestoreOnStop { get; set; } = true;
        public bool Restored { get; set; }
        public string RawFilterList { get; set; }
        public List<FilterRule> Rules { get; set; } = new List<FilterRule>();
        public List<string> UnparsedLines { get; set; } = new List<string>();
    }

    /// <summary>Sidecar <c>name.meta.json</c> written next to each .etl this tool records.</summary>
    public sealed class CaptureMeta
    {
        public string EtlFile { get; set; }
        public DateTime Started { get; set; }
        public DateTime? Stopped { get; set; }
        public string StoppedHow { get; set; }
        public List<int> ComponentIds { get; set; } = new List<int>();
        public List<string> ComponentNames { get; set; } = new List<string>();
        public bool Wireless { get; set; }
        public List<FilterRule> Filters { get; set; } = new List<FilterRule>();
        public int? PacketSize { get; set; }
        public string LogMode { get; set; }
        public int? FileSizeMb { get; set; }
        public string CommandLine { get; set; }
        public long? Packets { get; set; }
        /// <summary><c>name.attribution.json</c>: the process flow table recorded during the capture.</summary>
        public string AttributionFile { get; set; }
    }

    public sealed class PktmonStatus
    {
        public bool Running { get; set; }
        public string Raw { get; set; }
        public string LogFile { get; set; }
        public string LogMode { get; set; }
        public List<string> Components { get; set; } = new List<string>();
        public string CollectedData { get; set; }
        public string CaptureType { get; set; }
        public bool IsRealTime => LogMode != null && LogMode.IndexOf("real", StringComparison.OrdinalIgnoreCase) >= 0;
        public bool IsCountersOnly => CollectedData != null && CollectedData.IndexOf("capture", StringComparison.OrdinalIgnoreCase) < 0;
    }
}
