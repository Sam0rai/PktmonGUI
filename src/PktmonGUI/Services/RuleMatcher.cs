using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using PktmonGUI.Model;

namespace PktmonGUI.Services
{
    /// <summary>
    /// Per-rule tallies for Live mode. pktmon counters are per component, not per filter, so
    /// the rule a packet belongs to is taken from the "Filter N" field pktmon prints; when
    /// that's missing, the rule is matched here with pktmon's own semantics (fields ANDed,
    /// no source/destination distinction).
    /// </summary>
    public sealed class RuleMatcher
    {
        private readonly List<FilterRule> _rules;

        public RuleMatcher(IEnumerable<FilterRule> rules) { _rules = rules.ToList(); }

        public IReadOnlyList<FilterRule> Rules => _rules;

        /// <summary>0-based rule index, or -1 when no rule matches.</summary>
        public int Match(PacketRecord p)
        {
            if (p.FilterId.HasValue && p.FilterId.Value >= 1 && p.FilterId.Value <= _rules.Count)
                return p.FilterId.Value - 1;
            for (int i = 0; i < _rules.Count; i++)
                if (Matches(_rules[i], p)) return i;
            return -1;
        }

        public static bool Matches(FilterRule r, PacketRecord p)
        {
            if (r.Mac1 != null && !MacIn(r.Mac1, p) ) return false;
            if (r.Mac2 != null && !MacIn(r.Mac2, p)) return false;
            if (r.Vlan.HasValue && p.Vlan != r.Vlan) return false;

            if (r.EtherType != null)
            {
                var et = r.EtherType.ToUpperInvariant();
                bool ok;
                switch (et)
                {
                    case "IPV4": case "0X0800": ok = p.EtherType == "IPv4"; break;
                    case "IPV6": case "0X86DD": ok = p.EtherType == "IPv6"; break;
                    case "ARP": case "0X0806": ok = p.Protocol == "ARP"; break;
                    case "0X88CC": ok = p.Protocol == "LLDP"; break;
                    case "0X888E": ok = p.Protocol == "EAPOL"; break;
                    default: ok = string.Equals(p.EtherType, r.EtherType, StringComparison.OrdinalIgnoreCase); break;
                }
                if (!ok) return false;
            }

            if (r.Transport != null)
            {
                int? want = TransportNumber(r.Transport);
                if (want == null || p.IpProtocol != want) return false;
                if (r.IsTcp && r.TcpFlags != TcpFlags.None && (p.TcpFlags & r.TcpFlags) == 0) return false;
            }

            if (r.Ip1 != null && !IpIn(r.Ip1, p)) return false;
            if (r.Ip2 != null && !IpIn(r.Ip2, p)) return false;
            if (r.Port1.HasValue && p.SrcPort != r.Port1 && p.DstPort != r.Port1) return false;
            if (r.Port2.HasValue && p.SrcPort != r.Port2 && p.DstPort != r.Port2) return false;
            if (r.Heartbeat && p.SrcPort != 3343 && p.DstPort != 3343) return false;
            return true;
        }

        private static bool MacIn(string mac, PacketRecord p)
        {
            var m = FilterRule.NormalizeMac(mac);
            return string.Equals(p.SrcMac, m, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(p.DstMac, m, StringComparison.OrdinalIgnoreCase);
        }

        private static int? TransportNumber(string t)
        {
            switch (t.ToUpperInvariant())
            {
                case "TCP": return 6;
                case "UDP": return 17;
                case "ICMP": return 1;
                case "ICMPV6": return 58;
            }
            return FilterRule.TryParseNumber(t, out var n) ? (int)n : (int?)null;
        }

        private static bool IpIn(string spec, PacketRecord p) =>
            InSubnet(spec, p.SrcIp) || InSubnet(spec, p.DstIp);

        internal static bool InSubnet(string spec, string ip)
        {
            if (ip == null) return false;
            var parts = spec.Split('/');
            if (!IPAddress.TryParse(parts[0], out var net) || !IPAddress.TryParse(ip, out var addr)) return false;
            if (net.AddressFamily != addr.AddressFamily) return false;
            if (parts.Length == 1) return net.Equals(addr);
            int prefix = int.Parse(parts[1], CultureInfo.InvariantCulture);
            var a = net.GetAddressBytes();
            var b = addr.GetAddressBytes();
            for (int i = 0; i < a.Length && prefix > 0; i++, prefix -= 8)
            {
                int bits = Math.Min(8, prefix);
                int mask = 0xFF << (8 - bits) & 0xFF;
                if ((a[i] & mask) != (b[i] & mask)) return false;
            }
            return true;
        }
    }

    public sealed class RuleTally : System.ComponentModel.INotifyPropertyChanged
    {
        public RuleTally(FilterRule rule) { Rule = rule; }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        /// <summary>Counts change per packet; the UI is told once per batch.</summary>
        public void Notify() => PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(string.Empty));
        public FilterRule Rule { get; }
        public string Name => string.IsNullOrWhiteSpace(Rule.Name) ? Rule.ShortLabel : Rule.Name;
        public string Args => Rule.ArgsSummary;
        public long RxPackets { get; set; }
        public long RxBytes { get; set; }
        public long TxPackets { get; set; }
        public long TxBytes { get; set; }
        public long Total => RxPackets + TxPackets;

        public string Split
        {
            get
            {
                if (Total == 0) return "nothing yet";
                int rx = (int)Math.Round(100.0 * RxPackets / Total);
                var s = $"{rx}% in / {100 - rx}% out";
                if (RxPackets == 0) return s + " · nothing is coming back";
                if (TxPackets == 0) return s + " · inbound only";
                return s;
            }
        }
    }
}
