using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using PktmonGUI.Model;

namespace PktmonGUI.Parsing
{
    /// <summary>
    /// Turns pktmon's packet text (real-time mode and etl2txt use the same shape) into
    /// <see cref="PacketRecord"/>s. Every packet is a metadata line followed by a
    /// tcpdump-style body line:
    /// <code>
    /// [..]14:31:02.118204200 PktGroupId 1, PktNumber 1, Appearance 1, Direction Tx , Type Ethernet , Component 18, Edge 1, Filter 1, OriginalSize 92, LoggedSize 92
    ///     00-15-5D-01-2A-3F > 00-15-5D-04-11-A0, ethertype IPv4 (0x0800), length 92: 10.30.14.22.51422 > 10.30.14.10.53: 47182+ [1au] A? app-gw.contoso.local. (58)
    /// </code>
    /// A record is emitted as soon as its body line arrives, so a single packet shows up
    /// immediately instead of waiting for the next one. Later indented lines (verbose or
    /// hex output) are appended to the last record.
    /// </summary>
    public sealed class RealtimeParser
    {
        private PacketRecord _pendingMeta;   // metadata seen, body not yet
        private PacketRecord _last;          // last emitted, for continuation lines
        private long _counter, _eventCounter;

        public enum LineKind { Blank, Meta, Body, Continuation, Info, Event }

        /// <summary>What the most recent <see cref="Feed"/> call saw.</summary>
        public LineKind LastLineKind { get; private set; }

        /// <summary>
        /// The event the most recent <see cref="Feed"/> read, when <see cref="LastLineKind"/> is
        /// <see cref="LineKind.Event"/>; null otherwise.
        /// </summary>
        public EtwEventRecord LastEvent { get; private set; }

        private static readonly Regex MetaRx = new Regex(
            @"(PktGroupId|PktNumber)\s+\S+.*?Direction\s+(Rx|Tx)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex TimeRx = new Regex(
            @"(?:(?<date>\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})[ T\-])?(?<time>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)",
            RegexOptions.Compiled);

        private static readonly Regex KvRx = new Regex(@"(?<k>[A-Za-z]+)\s+(?<v>[^,]*?)\s*(?:,|$)", RegexOptions.Compiled);

        public static bool IsMetaLine(string line) => line != null && MetaRx.IsMatch(line);

        public IEnumerable<PacketRecord> Feed(string line)
        {
            var output = new List<PacketRecord>(1);
            LastEvent = null;
            if (line == null) return output;
            if (line.Trim().Length == 0) { LastLineKind = LineKind.Blank; return output; }

            if (IsMetaLine(line))
            {
                LastLineKind = LineKind.Meta;
                if (_pendingMeta != null) { Finish(_pendingMeta); output.Add(_pendingMeta); _last = _pendingMeta; }
                _pendingMeta = ParseMeta(line);
                return output;
            }

            // An extra provider's event (--trace -p). These interleave with the packets, so they are
            // read before a body line would be: one arriving between a packet's metadata and its body
            // must not be mistaken for that body. They also leave _pendingMeta and _last alone, so the
            // packet they interrupted still gets its body, and its continuation lines still reach it.
            if (TryParseEvent(line, out var evt))
            {
                LastLineKind = LineKind.Event;
                evt.Number = ++_eventCounter;
                LastEvent = evt;
                return output;
            }

            if (_pendingMeta != null)
            {
                LastLineKind = LineKind.Body;
                var rec = _pendingMeta;
                _pendingMeta = null;
                rec.RawLines.Add(line.TrimEnd());
                ParseBody(rec, line.Trim());
                Finish(rec);
                _last = rec;
                output.Add(rec);
                return output;
            }

            if (_last != null && (char.IsWhiteSpace(line[0]) || LooksLikeHex(line)))
            {
                LastLineKind = LineKind.Continuation;
                _last.RawLines.Add(line.TrimEnd());
                // Verbose output (etl2txt -v) wraps the IP pair onto the next line:
                //   ..., length 121: (tos 0x0, ttl 64, ..., proto UDP (17), length 107)
                //       192.168.7.228.44436 > 192.168.7.255.58866: UDP, length 79
                if (_last.SrcIp == null && !LooksLikeHex(line))
                {
                    var body = string.Join(" ", _last.RawLines.Skip(1).Select(l => l.Trim()));
                    Reset(_last);
                    ParseBody(_last, body);
                    if (_last.Info == null) _last.Info = "";
                }
                return output;
            }

            LastLineKind = LineKind.Info;
            _last = null;
            return output;
        }

        /// <summary>Emits a trailing metadata-only record (e.g. a drop with no body).</summary>
        public IEnumerable<PacketRecord> Flush()
        {
            if (_pendingMeta == null) yield break;
            var p = _pendingMeta;
            _pendingMeta = null;
            Finish(p);
            yield return p;
        }

        /// <summary>Parses a whole text (etl2txt output) in one go.</summary>
        public static List<PacketRecord> ParseAll(IEnumerable<string> lines, int max = int.MaxValue) =>
            ParseAll(lines, out _, max);

        /// <summary>As <see cref="ParseAll(IEnumerable{string}, int)"/>, also collecting any provider events.</summary>
        public static List<PacketRecord> ParseAll(IEnumerable<string> lines, out List<EtwEventRecord> events, int max = int.MaxValue)
        {
            var parser = new RealtimeParser();
            var list = new List<PacketRecord>();
            events = new List<EtwEventRecord>();
            foreach (var l in lines)
            {
                list.AddRange(parser.Feed(l));
                if (parser.LastLineKind == LineKind.Event) events.Add(parser.LastEvent);
                if (list.Count >= max) return list;
            }
            list.AddRange(parser.Flush());
            return list;
        }

        private void Finish(PacketRecord p)
        {
            p.Number = ++_counter;
            if (p.Info == null) p.Info = p.IsDrop ? "Dropped: " + (p.DropReason ?? "unknown reason") : "";
            if (p.Protocol == null) p.Protocol = p.MediaType ?? "?";
        }

        private static bool LooksLikeHex(string line) =>
            Regex.IsMatch(line, @"^\s*(0x)?[0-9a-fA-F]{4}:\s+[0-9a-fA-F]{2,4}(\s|$)");

        // ---- Events from extra ETW providers ------------------------------------
        //
        // Real-time prints them as a timestamp and pktmon's own label:
        //   16:42:03.343836100 TCPIP: Framing layer Receive (AddressFamily=IPV4) dropped 1 packet(s)
        //                             on interface=20, Reason=Invalid ethernet type, Data=0x86DD.
        // etl2txt names the provider instead:
        //   [00]0F30.1A20::2026-09-22 22:34:02.059736400 [Microsoft-Windows-TCPIP] Event: ...
        // Packet lines are matched before these, so neither shape can swallow one: a packet's
        // metadata is caught by MetaRx, and its body and continuation lines are indented.

        private static readonly Regex RealtimeEventRx = new Regex(
            @"^(?<time>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?<rest>\S.*?)\s*$", RegexOptions.Compiled);

        private static readonly Regex Etl2TxtEventRx = new Regex(
            @"^\[\d+\]\S*::(?:(?<date>\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})[ T])?(?<time>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[(?<provider>[^\]]+)\]\s*(?<rest>\S.*?)\s*$",
            RegexOptions.Compiled);

        /// <summary>pktmon's label for the event's source, e.g. "TCPIP: " or "INETINSPECT: ".</summary>
        private static readonly Regex EventSourceRx = new Regex(
            @"^(?<src>[A-Za-z][A-Za-z0-9_.-]*):\s+(?<text>\S.*)$", RegexOptions.Compiled);

        internal static bool TryParseEvent(string line, out EtwEventRecord e)
        {
            e = null;
            string time, date = null, provider = null, rest;

            var etl = Etl2TxtEventRx.Match(line);
            if (etl.Success)
            {
                time = etl.Groups["time"].Value;
                if (etl.Groups["date"].Success) date = etl.Groups["date"].Value;
                provider = etl.Groups["provider"].Value;
                rest = etl.Groups["rest"].Value;
            }
            else
            {
                var rt = RealtimeEventRx.Match(line);
                if (!rt.Success) return false;
                time = rt.Groups["time"].Value;
                rest = rt.Groups["rest"].Value;
                // Only real-time output carries pktmon's "TCPIP: " label; etl2txt already named
                // the provider, and its text ("Event: Header, ...") must keep its first word.
                var src = EventSourceRx.Match(rest);
                if (src.Success) { provider = src.Groups["src"].Value; rest = src.Groups["text"].Value; }
            }

            e = new EtwEventRecord
            {
                Timestamp = time,
                Time = ToTime(time, date),
                Source = provider,
                Text = rest,
                Raw = line.TrimEnd(),
            };
            return true;
        }

        /// <summary>pktmon's time of day, with etl2txt's date when it printed one.</summary>
        private static DateTime? ToTime(string time, string date)
        {
            var fmt = new[] { "H:mm:ss.FFFFFFF", "HH:mm:ss.FFFFFFF", "H:mm:ss", "HH:mm:ss" };
            var t = time.Length > 16 ? time.Substring(0, 16) : time;   // .NET: max 7 fractional digits
            if (!DateTime.TryParseExact(t, fmt, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
                return null;
            if (date != null && DateTime.TryParse(date, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
                parsed = d.Date + parsed.TimeOfDay;
            return parsed;
        }

        // ---- Metadata -----------------------------------------------------------

        internal static PacketRecord ParseMeta(string line)
        {
            var p = new PacketRecord();
            p.RawLines.Add(line.TrimEnd());

            int kvStart = line.IndexOf("PktGroupId", StringComparison.OrdinalIgnoreCase);
            if (kvStart < 0) kvStart = line.IndexOf("PktNumber", StringComparison.OrdinalIgnoreCase);
            var prefix = kvStart > 0 ? line.Substring(0, kvStart) : "";
            if (prefix.IndexOf("Drop:", StringComparison.Ordinal) >= 0) p.IsDrop = true;
            var tm = TimeRx.Match(prefix);
            if (tm.Success)
            {
                p.Timestamp = tm.Groups["time"].Value;
                p.Time = ToTime(p.Timestamp, tm.Groups["date"].Success ? tm.Groups["date"].Value : null);
            }

            foreach (Match m in KvRx.Matches(line.Substring(Math.Max(0, kvStart))))
            {
                var k = m.Groups["k"].Value;
                var v = m.Groups["v"].Value.Trim();
                switch (k.ToLowerInvariant())
                {
                    case "pktgroupid": p.PktGroupId = ToLong(v); break;
                    case "pktnumber": p.PktNumber = ToInt(v); break;
                    case "appearance": p.Appearance = ToInt(v); break;
                    case "direction":
                        p.Direction = v.StartsWith("Rx", StringComparison.OrdinalIgnoreCase) ? Direction.Rx
                                    : v.StartsWith("Tx", StringComparison.OrdinalIgnoreCase) ? Direction.Tx : Direction.Unknown;
                        break;
                    case "type": p.MediaType = v; break;
                    case "component": p.ComponentId = ToInt(v); break;
                    case "edge": p.Edge = ToInt(v); break;
                    case "filter": p.FilterId = ToInt(v); break;
                    case "originalsize": p.OriginalSize = ToInt(v); break;
                    case "loggedsize": p.LoggedSize = ToInt(v); break;
                    case "dropreason": p.IsDrop = true; p.DropReason = v; break;
                    case "droplocation": p.IsDrop = true; p.DropLocation = v; break;
                }
            }
            if (p.OriginalSize.HasValue && p.LoggedSize.HasValue && p.LoggedSize < p.OriginalSize)
                p.Truncated = true;
            return p;
        }

        private static int? ToInt(string s) =>
            int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : (int?)null;

        private static long? ToLong(string s) =>
            long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : (long?)null;

        // ---- Body (tcpdump style) ---------------------------------------------------

        private static readonly Regex EthRx = new Regex(
            @"^(?<src>[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s*>\s*(?<dst>[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5}),\s*(?<rest>.*)$",
            RegexOptions.Compiled);

        private static readonly Regex VlanRx = new Regex(@"^(?:ethertype 802\.1Q \(0x8100\), )?vlan (?<id>\d+), p \d+,\s*", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex EtherTypeRx = new Regex(
            @"^ethertype (?<name>[^(,]+?)\s*\((?<num>0x[0-9A-Fa-f]+)\), length (?<len>\d+):\s*(?<payload>.*)$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex Llc8023Rx = new Regex(@"^(?:802\.3, )?length (?<len>\d+):\s*(?<payload>.*)$", RegexOptions.Compiled);

        // The destination ends at the first colon followed by whitespace; IPv6 "::" never is.
        private static readonly Regex IpPairRx = new Regex(@"^(?<src>\S+) > (?<dst>\S+?):(?:\s+(?<rest>.*))?$", RegexOptions.Compiled);

        /// <summary>
        /// pktmon's raw-IP printer. Media with no link-layer header — mobile broadband (WWAN)
        /// adapters, which report <c>Type IP</c> — print the IP packet behind a bare <c>ip: </c>
        /// instead of a MAC pair and an ethertype:
        /// <code>    ip: 100.64.12.34.54564 > 203.0.113.1.53: 5403+ A? example.com. (29)</code>
        /// pktmon has one such prefix for both families (its ether_if / raw_if / 802.11_if
        /// printers), so the address decides whether this is IPv4 or IPv6.
        /// </summary>
        private static readonly Regex RawIpRx = new Regex(@"^ip6?:\s*", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static void Reset(PacketRecord p)
        {
            p.SrcMac = p.DstMac = p.EtherType = p.Source = p.Destination = p.SrcIp = p.DstIp = null;
            p.Protocol = p.Info = p.Payload = p.IpHeader = null;
            p.SrcPort = p.DstPort = p.IpProtocol = p.Vlan = null;
            p.TcpFlags = TcpFlags.None;
        }

        internal static void ParseBody(PacketRecord p, string body)
        {
            // Drop records repeat the "Drop: " marker on the body line.
            if (body.StartsWith("Drop:", StringComparison.Ordinal)) { p.IsDrop = true; body = body.Substring(5).TrimStart(); }

            // Raw IP (WWAN): no link header, so there is no ethertype token to read the family from.
            var raw = RawIpRx.Match(body);
            if (raw.Success)
            {
                var ip = body.Substring(raw.Length);
                p.EtherType = RawIpFamily(ip);
                TryParseIpPayload(p, ip);
                return;
            }

            var eth = EthRx.Match(body);
            if (!eth.Success)
            {
                // Other non-Ethernet media (Wi-Fi native 802.11) — keep it readable.
                p.Info = body;
                TryParseIpPayload(p, body);
                return;
            }

            p.SrcMac = eth.Groups["src"].Value.ToUpperInvariant().Replace(':', '-');
            p.DstMac = eth.Groups["dst"].Value.ToUpperInvariant().Replace(':', '-');
            var rest = eth.Groups["rest"].Value;

            var vlan = VlanRx.Match(rest);
            if (vlan.Success)
            {
                p.Vlan = int.Parse(vlan.Groups["id"].Value, CultureInfo.InvariantCulture);
                rest = rest.Substring(vlan.Length);
            }

            var et = EtherTypeRx.Match(rest);
            string payload;
            if (et.Success)
            {
                p.EtherType = et.Groups["name"].Value.Trim();
                payload = et.Groups["payload"].Value;
                var num = et.Groups["num"].Value.ToLowerInvariant();
                switch (num)
                {
                    case "0x0800":
                    case "0x86dd":
                        TryParseIpPayload(p, payload);
                        break;
                    case "0x0806":
                        p.Protocol = "ARP";
                        p.Info = payload.Trim();
                        break;
                    case "0x88cc":
                        p.Protocol = "LLDP";
                        p.Info = payload.Trim();
                        break;
                    case "0x888e":
                        p.Protocol = "EAPOL";
                        p.Info = payload.Trim();
                        break;
                    default:
                        p.Protocol = p.EtherType;
                        p.Info = payload.Trim();
                        break;
                }
            }
            else
            {
                var llc = Llc8023Rx.Match(rest);
                payload = llc.Success ? llc.Groups["payload"].Value : rest;
                p.EtherType = "802.3";
                if (payload.IndexOf("CDP", StringComparison.Ordinal) >= 0) p.Protocol = "CDP";
                else if (payload.IndexOf("STP", StringComparison.Ordinal) >= 0 || payload.IndexOf("802.1d", StringComparison.OrdinalIgnoreCase) >= 0) p.Protocol = "STP";
                else if (payload.IndexOf("LLDP", StringComparison.Ordinal) >= 0) p.Protocol = "LLDP";
                else p.Protocol = "LLC";
                p.Info = payload.Trim();
            }
            if (p.DstMac == "01-00-0C-CC-CC-CC" && p.Protocol != "CDP") p.Protocol = "CDP";
            p.Payload = payload;
            if (payload.TrimEnd().EndsWith("|", StringComparison.Ordinal) || payload.Contains("[|")) p.Truncated = true;
        }

        // Verbose IP header summary: "(tos 0x0, ttl 64, id 1, offset 0, flags [DF], proto UDP (17), length 107) "
        // or "(class 0x88, flowlabel 0x1, hlim 60, next-header TCP (6) payload length: 32) ".
        private static readonly Regex IpHeaderRx = new Regex(@"^\((?<h>(?:[^()]|\([^()]*\))*)\)\s*", RegexOptions.Compiled);

        /// <summary>
        /// "IPv6" when the source endpoint of a raw-IP body is a v6 address, else "IPv4". The
        /// verbose header is skipped first because it carries colons of its own
        /// ("next-header TCP (6) payload length: 32").
        /// </summary>
        private static string RawIpFamily(string body)
        {
            var hdr = IpHeaderRx.Match(body);
            if (hdr.Success) body = body.Substring(hdr.Length);
            int gt = body.IndexOf(" > ", StringComparison.Ordinal);
            var src = gt > 0 ? body.Substring(0, gt) : body;
            return src.IndexOf(':') >= 0 ? "IPv6" : "IPv4";
        }

        private static void TryParseIpPayload(PacketRecord p, string payload)
        {
            p.Payload = payload;
            var hdr = IpHeaderRx.Match(payload);
            if (hdr.Success)
            {
                p.IpHeader = hdr.Groups["h"].Value;
                payload = payload.Substring(hdr.Length);
            }
            var m = IpPairRx.Match(payload);
            if (!m.Success)
            {
                if (p.Protocol == null) p.Protocol = p.EtherType;
                p.Info = payload.Trim();
                return;
            }

            SplitEndpoint(m.Groups["src"].Value, out var sip, out var sport);
            SplitEndpoint(m.Groups["dst"].Value, out var dip, out var dport);
            p.SrcIp = sip; p.SrcPort = sport;
            p.DstIp = dip; p.DstPort = dport;
            p.Source = m.Groups["src"].Value;
            p.Destination = m.Groups["dst"].Value;
            var rest = m.Groups["rest"].Value.Trim();
            p.Info = rest;

            if (rest.StartsWith("Flags [", StringComparison.Ordinal))
            {
                p.Protocol = "TCP";
                p.IpProtocol = 6;
                p.TcpFlags = ParseTcpFlags(rest);
            }
            else if (rest.StartsWith("ICMP6", StringComparison.Ordinal) || rest.StartsWith("ICMPv6", StringComparison.Ordinal))
            {
                p.Protocol = "ICMPv6"; p.IpProtocol = 58;
            }
            else if (rest.StartsWith("ICMP", StringComparison.Ordinal))
            {
                p.Protocol = "ICMP"; p.IpProtocol = 1;
            }
            else if (rest.StartsWith("igmp", StringComparison.OrdinalIgnoreCase)) { p.Protocol = "IGMP"; p.IpProtocol = 2; }
            else if (rest.StartsWith("GREv", StringComparison.Ordinal) || rest.StartsWith("GRE", StringComparison.Ordinal)) { p.Protocol = "GRE"; p.IpProtocol = 47; }
            else if (rest.StartsWith("ESP", StringComparison.Ordinal)) { p.Protocol = "ESP"; p.IpProtocol = 50; }
            else if (rest.StartsWith("OSPF", StringComparison.Ordinal)) { p.Protocol = "OSPF"; p.IpProtocol = 89; }
            else if (rest.StartsWith("VRRP", StringComparison.Ordinal)) { p.Protocol = "VRRP"; p.IpProtocol = 112; }
            else if (sport.HasValue || dport.HasValue)
            {
                p.IpProtocol = 17;
                p.Protocol = UdpAppProtocol(sport, dport, rest);
            }
            else p.Protocol = p.EtherType == "IPv6" ? "IPv6" : "IPv4";
        }

        /// <summary>
        /// tcpdump writes the port after the last dot: <c>10.1.2.3.443</c>, <c>fe80::1.546</c>.
        /// An IPv4 address with exactly four parts has no port.
        /// </summary>
        internal static void SplitEndpoint(string ep, out string ip, out int? port)
        {
            ip = ep; port = null;
            int dot = ep.LastIndexOf('.');
            if (dot <= 0) return;
            bool v6 = ep.IndexOf(':') >= 0;
            if (!v6 && ep.Split('.').Length != 5) return;
            var tail = ep.Substring(dot + 1);
            if (int.TryParse(tail, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n <= 65535)
            {
                ip = ep.Substring(0, dot);
                port = n;
            }
            else if (!v6) return;
            else
            {
                // service name instead of number, e.g. fe80::1.dhcpv6-client
                ip = ep.Substring(0, dot);
            }
        }

        internal static TcpFlags ParseTcpFlags(string rest)
        {
            int a = rest.IndexOf('['), b = rest.IndexOf(']');
            if (a < 0 || b < a) return TcpFlags.None;
            var f = TcpFlags.None;
            foreach (var c in rest.Substring(a + 1, b - a - 1))
            {
                switch (c)
                {
                    case 'S': f |= TcpFlags.SYN; break;
                    case 'F': f |= TcpFlags.FIN; break;
                    case 'R': f |= TcpFlags.RST; break;
                    case 'P': f |= TcpFlags.PSH; break;
                    case '.': f |= TcpFlags.ACK; break;
                    case 'U': f |= TcpFlags.URG; break;
                    case 'E': f |= TcpFlags.ECE; break;
                    case 'W': f |= TcpFlags.CWR; break;
                }
            }
            return f;
        }

        private static readonly Regex DnsRx = new Regex(@"^\d+[+*\-$|]*\s", RegexOptions.Compiled);

        private static string UdpAppProtocol(int? s, int? d, string rest)
        {
            bool Port(int n) => s == n || d == n;
            if (Port(53) && (DnsRx.IsMatch(rest) || rest.Contains("?"))) return "DNS";
            if (Port(53)) return "DNS";
            if (Port(5353)) return "mDNS";
            if (Port(5355)) return "LLMNR";
            if (Port(67) || Port(68)) return "DHCP";
            if (Port(546) || Port(547)) return "DHCPv6";
            if (Port(123)) return "NTP";
            if (Port(137)) return "NBNS";
            if (Port(138)) return "NBDS";
            if (Port(161) || Port(162)) return "SNMP";
            if (Port(514)) return "Syslog";
            if (Port(1900)) return "SSDP";
            if (Port(3343)) return "Heartbeat";
            if (Port(4789)) return "VXLAN";
            if (Port(88)) return "Kerberos";
            if (Port(389)) return "CLDAP";
            if (Port(443)) return "QUIC";
            if (Port(3389)) return "RDP-UDP";
            if (Port(500) || Port(4500)) return "IKE";
            return "UDP";
        }

        internal static string TcpAppName(int? s, int? d)
        {
            int? p = WellKnown(d) ? d : WellKnown(s) ? s : null;
            if (p == null) return null;
            switch (p.Value)
            {
                case 20: case 21: return "FTP";
                case 22: return "SSH";
                case 23: return "Telnet";
                case 25: return "SMTP";
                case 53: return "DNS over TCP";
                case 80: return "HTTP";
                case 88: return "Kerberos";
                case 135: return "RPC endpoint mapper";
                case 139: return "NetBIOS session";
                case 389: return "LDAP";
                case 443: return "HTTPS";
                case 445: return "SMB";
                case 464: return "Kerberos password";
                case 636: return "LDAPS";
                case 1433: return "SQL Server";
                case 3268: return "Global Catalog";
                case 3269: return "Global Catalog (TLS)";
                case 3389: return "RDP";
                case 5985: return "WinRM";
                case 5986: return "WinRM (TLS)";
                case 8080: return "HTTP alt";
                case 9389: return "AD Web Services";
                default: return null;
            }
        }

        private static bool WellKnown(int? p) => p.HasValue && (p < 1024 || p == 1433 || p == 3268 || p == 3269 || p == 3389 || p == 5985 || p == 5986 || p == 8080 || p == 9389);
    }
}
