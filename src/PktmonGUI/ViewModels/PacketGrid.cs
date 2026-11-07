using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using CommunityToolkit.Mvvm.ComponentModel;
using PktmonGUI.Model;
using PktmonGUI.Services;

namespace PktmonGUI.ViewModels
{
    /// <summary>The packet grid's columns; the key is also each DataGridColumn's SortMemberPath.</summary>
    public static class PacketColumns
    {
        public const string Number = "Number", Time = "Time", Dir = "Dir", Source = "Source", SrcPort = "SrcPort",
                            Destination = "Destination", DstPort = "DstPort",
                            Protocol = "Protocol", Process = "Process", Bytes = "Bytes", Info = "Info";

        /// <summary>In the order the grid shows them: the port sits beside its address, not inside it.</summary>
        public static readonly string[] All = { Number, Time, Dir, Source, SrcPort, Destination, DstPort, Protocol, Process, Bytes, Info };

        public static string Title(string key)
        {
            switch (key)
            {
                case Number: return "#";
                case Dir: return "DIR";
                case Protocol: return "PROTO";
                case SrcPort: return "SRC PORT";
                case DstPort: return "DST PORT";
                default: return key.ToUpperInvariant();
            }
        }

        public static string Help(string key)
        {
            const string common = "\nSeparate alternatives with |. Start a term with ! to exclude it, e.g. !ARP|!STP.";
            switch (key)
            {
                case Number:
                case Bytes:
                    return "Numbers: 1500, >1000, <=60, 100-200" + common;
                case Time:
                    return "Time of day: >18:23:26, <18:23:30.5, 18:23:26-18:23:27, or any part of the time" + common;
                case Source:
                case Destination:
                    return "Address text (10.0.0.5), a subnet (10.0.0.0/8, fe80::/10), or a port (:443)" + common;
                case SrcPort:
                case DstPort:
                    return "Port numbers: 443, >1024, <1024, 8000-8100. Packets with no port (ARP, ICMP) never match" + common;
                case Process:
                    return "Process name, service or image path (chrome, Dnscache, \\Windows\\Temp\\), or a PID (4312). DNS sent by Dnscache matches the process it was for too" + common;
                case Dir:
                    return "in or out (pktmon's rx and tx work too)" + common;
                default:
                    return "Text anywhere in the column; =TCP for an exact match" + common;
            }
        }
    }

    /// <summary>One column's filter box.</summary>
    public sealed partial class ColumnFilter : ObservableObject
    {
        public ColumnFilter(string key)
        {
            Key = key;
            Title = PacketColumns.Title(key);
            Help = PacketColumns.Help(key);
        }

        public string Key { get; }
        public string Title { get; }
        public string Help { get; }

        [ObservableProperty] private string _text;

        public bool IsActive => !string.IsNullOrWhiteSpace(Text);
        partial void OnTextChanged(string value) => OnPropertyChanged(nameof(IsActive));
    }

    /// <summary>
    /// Turns a column filter's text into a predicate. Alternatives are separated by |; positive
    /// terms are ORed, terms starting with ! must all hold ("!ARP|!STP" hides both).
    /// </summary>
    public static class PacketFilter
    {
        public static Func<PacketRecord, bool> Compile(string column, string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;
            var positives = new List<Func<PacketRecord, bool>>();
            var negatives = new List<Func<PacketRecord, bool>>();
            foreach (var raw in text.Split('|'))
            {
                var term = raw.Trim();
                if (term.Length == 0) continue;
                bool negate = term.StartsWith("!", StringComparison.Ordinal);
                if (negate) term = term.Substring(1).Trim();
                if (term.Length == 0) continue;
                var test = Term(column, term);
                (negate ? negatives : positives).Add(test);
            }
            if (positives.Count == 0 && negatives.Count == 0) return null;
            return p =>
            {
                if (positives.Count > 0 && !positives.Any(t => t(p))) return false;
                foreach (var n in negatives) if (n(p)) return false;
                return true;
            };
        }

        private static Func<PacketRecord, bool> Term(string column, string term)
        {
            switch (column)
            {
                case PacketColumns.Number: return Numeric(term, p => p.Number);
                case PacketColumns.Bytes: return Numeric(term, p => p.Length);
                case PacketColumns.Time: return TimeTerm(term);
                case PacketColumns.Source: return Address(term, p => p.SrcIp, p => p.SrcPort, p => p.Source ?? p.SrcMac);
                case PacketColumns.Destination: return Address(term, p => p.DstIp, p => p.DstPort, p => p.Destination ?? p.DstMac);
                case PacketColumns.SrcPort: return Port(term, p => p.SrcPort);
                case PacketColumns.DstPort: return Port(term, p => p.DstPort);
                case PacketColumns.Process: return ProcessTerm(term);
                case PacketColumns.Dir: return Text(DirTerm(term), p => p.DirText);
                case PacketColumns.Protocol: return Text(term, p => p.Protocol);
                default: return Text(term, p => p.Info);
            }
        }

        /// <summary>The grid shows Inbound/Outbound; pktmon's own rx/tx still work as terms.</summary>
        private static string DirTerm(string term)
        {
            bool exact = term.StartsWith("=", StringComparison.Ordinal);
            var t = exact ? term.Substring(1).Trim() : term;
            if (t.Equals("rx", StringComparison.OrdinalIgnoreCase)) t = "Inbound";
            else if (t.Equals("tx", StringComparison.OrdinalIgnoreCase)) t = "Outbound";
            return exact ? "=" + t : t;
        }

        private static Func<PacketRecord, bool> Text(string term, Func<PacketRecord, string> get)
        {
            if (term.StartsWith("=", StringComparison.Ordinal))
            {
                var exact = term.Substring(1).Trim();
                return p => string.Equals(get(p), exact, StringComparison.OrdinalIgnoreCase);
            }
            return p => (get(p) ?? "").IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool TryNumber(string s, out double v) =>
            double.TryParse(s.Trim().Replace(",", ""), NumberStyles.Float, CultureInfo.InvariantCulture, out v);

        /// <summary>Comparison (&gt;, &gt;=, &lt;, &lt;=, =), range (a-b) or equality; null if the term isn't one.</summary>
        private static Func<double, bool> Comparison(string term, Func<string, (bool ok, double v)> parse)
        {
            foreach (var op in new[] { ">=", "<=", ">", "<", "=" })
                if (term.StartsWith(op, StringComparison.Ordinal))
                {
                    var (ok, v) = parse(term.Substring(op.Length));
                    if (!ok) return null;
                    switch (op)
                    {
                        case ">=": return x => x >= v;
                        case "<=": return x => x <= v;
                        case ">": return x => x > v;
                        case "<": return x => x < v;
                        default: return x => x == v;
                    }
                }
            // a-b (for times the dash can't be confused with a negative number)
            int dash = term.IndexOf('-', 1);
            if (dash > 0)
            {
                var (ok1, a) = parse(term.Substring(0, dash));
                var (ok2, b) = parse(term.Substring(dash + 1));
                if (ok1 && ok2) return x => x >= Math.Min(a, b) && x <= Math.Max(a, b);
            }
            var (ok3, e) = parse(term);
            return ok3 ? x => x == e : (Func<double, bool>)null;
        }

        /// <summary>
        /// Like <see cref="Numeric"/>, but a packet with no port (ARP, ICMP, a bare IP packet)
        /// has nothing to compare and so matches nothing rather than counting as 0.
        /// </summary>
        private static Func<PacketRecord, bool> Port(string term, Func<PacketRecord, int?> get)
        {
            var inner = Numeric(term, p => get(p) ?? 0);
            return p => get(p).HasValue && inner(p);
        }

        private static Func<PacketRecord, bool> Numeric(string term, Func<PacketRecord, double> get)
        {
            var cmp = Comparison(term, s => TryNumber(s, out var v) ? (true, v) : (false, 0));
            if (cmp != null) return p => cmp(get(p));
            return p => get(p).ToString(CultureInfo.InvariantCulture).IndexOf(term, StringComparison.Ordinal) >= 0;
        }

        private static (bool, double) ParseTimeOfDay(string s)
        {
            s = s.Trim();
            var formats = new[] { @"h\:mm\:ss\.FFFFFFF", @"h\:mm\:ss", @"h\:mm" };
            if (TimeSpan.TryParseExact(s, formats, CultureInfo.InvariantCulture, out var ts)) return (true, ts.TotalSeconds);
            return (false, 0);
        }

        private static Func<PacketRecord, bool> TimeTerm(string term)
        {
            var cmp = Comparison(term, ParseTimeOfDay);
            if (cmp != null) return p => p.Time.HasValue && cmp(p.Time.Value.TimeOfDay.TotalSeconds);
            return p => (p.Timestamp ?? "").IndexOf(term, StringComparison.Ordinal) >= 0;
        }

        private static Func<PacketRecord, bool> Address(string term, Func<PacketRecord, string> ip, Func<PacketRecord, int?> port, Func<PacketRecord, string> text)
        {
            if (term.StartsWith(":", StringComparison.Ordinal) && int.TryParse(term.Substring(1), out var want))
                return p => port(p) == want;
            if (term.IndexOf('/') > 0 && FilterRule.IsIpOrCidr(term))
                return p => ip(p) != null && RuleMatcher.InSubnet(term, ip(p));
            if (IPAddress.TryParse(term, out var exact) && (term.IndexOf(':') >= 0 || term.Count(c => c == '.') == 3))
            {
                var norm = exact.ToString();
                return p => ip(p) != null && IPAddress.TryParse(ip(p), out var a) && a.ToString() == norm;
            }
            return Text(term, text);
        }

        private static Func<PacketRecord, bool> ProcessTerm(string term)
        {
            if (int.TryParse(term, NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
                return p => p.Attribution?.Pid == pid || p.Attribution?.RequesterPid == pid;
            return p =>
            {
                var a = p.Attribution;
                if (a == null) return false;
                bool Has(string s) => s != null && s.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
                return Has(a.Name) || Has(a.Services) || Has(a.Text) || Has(a.Path) || Has(a.RequesterPath);
            };
        }
    }

    /// <summary>Typed comparers for the packet grid (a string sort would put 10.0.0.10 before 10.0.0.9).</summary>
    public sealed class PacketComparer : IComparer
    {
        private readonly string _column;
        private readonly int _sign;

        public PacketComparer(string column, ListSortDirection direction)
        {
            _column = column;
            _sign = direction == ListSortDirection.Ascending ? 1 : -1;
        }

        public int Compare(object x, object y)
        {
            var a = (PacketRecord)x;
            var b = (PacketRecord)y;
            int c = CompareBy(a, b);
            // Ties keep capture order, whichever way the column sorts.
            return c != 0 ? _sign * c : a.Number.CompareTo(b.Number);
        }

        private int CompareBy(PacketRecord a, PacketRecord b)
        {
            switch (_column)
            {
                case PacketColumns.Number: return a.Number.CompareTo(b.Number);
                case PacketColumns.Time: return Nullable.Compare(a.Time, b.Time);
                case PacketColumns.Dir: return string.CompareOrdinal(a.DirText, b.DirText);
                case PacketColumns.Source: return string.CompareOrdinal(AddressKey(a, true), AddressKey(b, true));
                case PacketColumns.Destination: return string.CompareOrdinal(AddressKey(a, false), AddressKey(b, false));
                case PacketColumns.SrcPort: return PortCompare(a.SrcPort, b.SrcPort);
                case PacketColumns.DstPort: return PortCompare(a.DstPort, b.DstPort);
                case PacketColumns.Protocol: return string.Compare(a.Protocol, b.Protocol, StringComparison.OrdinalIgnoreCase);
                case PacketColumns.Bytes: return a.Length.CompareTo(b.Length);
                case PacketColumns.Process: return ProcessCompare(a, b);
                default: return string.Compare(a.Info, b.Info, StringComparison.OrdinalIgnoreCase);
            }
        }

        /// <summary>Ports numerically; packets without one (ARP, ICMP) after all that have one.</summary>
        private static int PortCompare(int? a, int? b)
        {
            if (a.HasValue && b.HasValue) return a.Value.CompareTo(b.Value);
            if (a.HasValue == b.HasValue) return 0;
            return a.HasValue ? -1 : 1;
        }

        /// <summary>Processes by name, then PID; packets without one after all named ones.</summary>
        private static int ProcessCompare(PacketRecord a, PacketRecord b)
        {
            int Rank(PacketRecord p)
            {
                switch (p.Attribution?.State)
                {
                    case Attribution.AttributionState.Resolved:
                    case Attribution.AttributionState.System: return 0;
                    case Attribution.AttributionState.Pending: return 1;
                    case Attribution.AttributionState.Unknown: return 2;
                    case Attribution.AttributionState.NoProcess: return 3;
                    default: return 4;
                }
            }
            int r = Rank(a).CompareTo(Rank(b));
            if (r != 0) return r;
            int n = string.Compare(a.Attribution?.Name, b.Attribution?.Name, StringComparison.OrdinalIgnoreCase);
            return n != 0 ? n : Nullable.Compare(a.Attribution?.Pid, b.Attribution?.Pid);
        }

        /// <summary>A sortable key: IPv4 before IPv6, addresses byte-wise, then port numerically; non-IP by MAC.</summary>
        internal static string AddressKey(PacketRecord p, bool source)
        {
            var cached = source ? p.SrcSortKey : p.DstSortKey;
            if (cached != null) return cached;
            var ip = source ? p.SrcIp : p.DstIp;
            var port = source ? p.SrcPort : p.DstPort;
            string key;
            if (ip != null && IPAddress.TryParse(ip, out var addr))
            {
                var bytes = addr.GetAddressBytes();
                key = (addr.AddressFamily == AddressFamily.InterNetwork ? "4" : "6") + BitConverter.ToString(bytes) + "#" + (port ?? -1).ToString("D5", CultureInfo.InvariantCulture);
            }
            else key = "~" + (source ? p.SrcMac : p.DstMac);
            if (source) p.SrcSortKey = key; else p.DstSortKey = key;
            return key;
        }
    }
}
