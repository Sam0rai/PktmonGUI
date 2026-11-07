using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using PktmonGUI.Model;

namespace PktmonGUI.Parsing.Decoders
{
    /// <summary>
    /// Builds the "Decoded" pane and the symbol legend from pktmon's tcpdump-style text.
    /// pktmon real-time mode prints text, not bytes, so everything here is read back
    /// from that text: nothing is invented that pktmon didn't print.
    /// </summary>
    public static class PacketDecoder
    {
        public static List<DecodedSection> Decode(PacketRecord p, out List<SymbolLegend> legend)
        {
            legend = new List<SymbolLegend>();
            var sections = new List<DecodedSection> { Frame(p) };
            if (p.Attribution != null) sections.Add(Process(p.Attribution));

            if (p.SrcMac != null)
            {
                var eth = new DecodedSection("Ethernet",
                    new DecodedField("Source", p.SrcMac),
                    new DecodedField("Destination", p.DstMac + MacNote(p.DstMac)));
                if (p.Vlan.HasValue) eth.Fields.Add(new DecodedField("VLAN", p.Vlan.ToString()));
                if (p.EtherType != null) eth.Fields.Add(new DecodedField("EtherType", EtherTypeText(p)));
                sections.Add(eth);
            }

            try
            {
                switch (p.Protocol)
                {
                    case "TCP": sections.AddRange(Tcp.Decode(p, legend)); break;
                    case "DNS": case "mDNS": case "LLMNR": sections.AddRange(Dns.Decode(p, legend)); break;
                    case "ICMP": case "ICMPv6": sections.AddRange(Icmp.Decode(p, legend)); break;
                    case "ARP": sections.Add(Arp.Decode(p, legend)); break;
                    case "LLDP": case "CDP": sections.Add(Discovery.Decode(p, legend)); break;
                    default:
                        if (p.SrcIp != null) sections.Add(IpSection(p, p.Protocol));
                        break;
                }
            }
            catch (Exception ex)
            {
                sections.Add(new DecodedSection("Decoder", new DecodedField("Error", ex.Message, FieldTone.Warn)));
            }

            if (p.Truncated)
                legend.Add(new SymbolLegend("|", "Packet was cut at the snap length; capture with --pkt-size 0 for all of it"));
            return sections;
        }

        private static DecodedSection Process(Attribution.ProcessAttribution a)
        {
            var s = new DecodedSection("Process");
            switch (a.State)
            {
                case Attribution.AttributionState.Pending:
                    s.Fields.Add(new DecodedField("Process", "waiting for the ETW event that names this flow", FieldTone.Warn));
                    break;
                case Attribution.AttributionState.NoProcess:
                    s.Fields.Add(new DecodedField("Process", "none on this machine"));
                    s.Fields.Add(new DecodedField("Why", a.Reason));
                    break;
                case Attribution.AttributionState.Unknown:
                    s.Fields.Add(new DecodedField("Process", "not found", FieldTone.Warn));
                    s.Fields.Add(new DecodedField("Why", a.Reason ?? "no socket event or connection-table entry matched this flow"));
                    break;
                default:
                    s.Fields.Add(new DecodedField("Name", a.Name, FieldTone.Good));
                    s.Fields.Add(new DecodedField("PID", a.Pid?.ToString()));
                    if (a.Path != null) s.Fields.Add(new DecodedField("Path", a.Path));
                    if (a.Services != null) s.Fields.Add(new DecodedField("Services", a.Services));
                    if (a.RequesterPid != null)
                    {
                        s.Fields.Add(new DecodedField("Requested by", a.RequesterText, FieldTone.Good));
                        if (a.RequesterPath != null) s.Fields.Add(new DecodedField("Requester path", a.RequesterPath));
                    }
                    else if (a.RequesterNote != null) s.Fields.Add(new DecodedField("Requested by", a.RequesterNote, FieldTone.Warn));
                    if (a.State == Attribution.AttributionState.System)
                        s.Fields.Add(new DecodedField("Note", $"PID 4 is the kernel ({a.Reason}). Kernel-mode servers such as SMB and HTTP.sys own their sockets there."));
                    if (a.RequesterPid != null || a.RequesterNote != null)
                        s.Fields.Add(new DecodedField("Note", "Programs that resolve names through Windows don't send DNS themselves: the DNS Client service (Dnscache) " +
                                                              "sends it from its own socket. Dnscache logs which process each query is for (DNS-Client event 3010); " +
                                                              "the packet is matched to that event by name, type and server."));
                    if (a.Source != null) s.Fields.Add(new DecodedField("Attributed by", a.Source));
                    break;
            }
            return s;
        }

        private static DecodedSection Frame(PacketRecord p)
        {
            var s = new DecodedSection("Frame");
            if (p.Timestamp != null) s.Fields.Add(new DecodedField("Captured", p.Timestamp));
            s.Fields.Add(new DecodedField("Direction", p.Direction == Direction.Rx ? "RX (inbound)" : p.Direction == Direction.Tx ? "TX (outbound)" : "unknown"));
            if (p.ComponentId.HasValue) s.Fields.Add(new DecodedField("Component", p.ComponentId.ToString()));
            if (p.Edge.HasValue) s.Fields.Add(new DecodedField("Edge", p.Edge.ToString()));
            if (p.FilterId.HasValue) s.Fields.Add(new DecodedField("Matched filter", p.FilterId == 0 ? "none (no filters set)" : "#" + p.FilterId));
            if (p.OriginalSize.HasValue) s.Fields.Add(new DecodedField("Original size", p.OriginalSize + " bytes"));
            if (p.LoggedSize.HasValue && p.LoggedSize != p.OriginalSize)
                s.Fields.Add(new DecodedField("Logged size", p.LoggedSize + " bytes (truncated)", FieldTone.Warn));
            if (p.MediaType != null && p.MediaType != "Ethernet") s.Fields.Add(new DecodedField("Media", p.MediaType));
            if (p.Appearance.HasValue && p.Appearance > 1)
                s.Fields.Add(new DecodedField("Appearance", $"{p.Appearance} (same packet seen again at another component)", FieldTone.Warn));
            if (p.IsDrop)
            {
                s.Fields.Add(new DecodedField("Dropped", p.DropReason ?? "yes", FieldTone.Bad));
                if (p.DropLocation != null) s.Fields.Add(new DecodedField("Drop location", p.DropLocation));
            }
            if (p.OriginalSize.HasValue && p.MediaType == "Ethernet")
                s.Fields.Add(new DecodedField("Note", "size excludes the 4-byte FCS"));
            return s;
        }

        private static string MacNote(string mac)
        {
            if (mac == null) return "";
            if (mac == "FF-FF-FF-FF-FF-FF") return " (broadcast)";
            if (mac == "01-00-0C-CC-CC-CC") return " (CDP/VTP multicast)";
            if (mac == "01-80-C2-00-00-0E") return " (LLDP nearest bridge)";
            if (mac.StartsWith("01-00-5E", StringComparison.Ordinal)) return " (IPv4 multicast)";
            if (mac.StartsWith("33-33", StringComparison.Ordinal)) return " (IPv6 multicast)";
            return "";
        }

        private static string EtherTypeText(PacketRecord p)
        {
            var m = Regex.Match(p.RawLines.Count > 1 ? p.RawLines[1] : "", @"ethertype [^(,]+\((0x[0-9a-fA-F]+)\)");
            return m.Success ? $"{p.EtherType} ({m.Groups[1].Value})" : p.EtherType;
        }

        internal static DecodedSection IpSection(PacketRecord p, string transport)
        {
            var name = (p.EtherType == "IPv6" ? "IPv6" : "IPv4") + (transport != null && transport != "IPv4" && transport != "IPv6" ? " / " + transport : "");
            var s = new DecodedSection(name,
                new DecodedField("Source", p.SrcIp + (p.SrcPort.HasValue ? ":" + p.SrcPort : "")),
                new DecodedField("Destination", p.DstIp + (p.DstPort.HasValue ? ":" + p.DstPort : "")));
            if (p.IpProtocol.HasValue) s.Fields.Add(new DecodedField("Protocol", $"{ProtoName(p.IpProtocol.Value)} ({p.IpProtocol})"));
            var len = Regex.Match(p.Info ?? "", @"length (\d+)");
            if (len.Success) s.Fields.Add(new DecodedField("Payload length", len.Groups[1].Value + " bytes"));
            if (p.Info != null && !string.IsNullOrWhiteSpace(p.Info)) s.Fields.Add(new DecodedField("pktmon says", p.Info));
            return s;
        }

        internal static string ProtoName(int n)
        {
            switch (n)
            {
                case 1: return "ICMP";
                case 2: return "IGMP";
                case 6: return "TCP";
                case 17: return "UDP";
                case 47: return "GRE";
                case 50: return "ESP";
                case 58: return "ICMPv6";
                case 89: return "OSPF";
                case 112: return "VRRP";
                default: return n.ToString(CultureInfo.InvariantCulture);
            }
        }
    }

    internal static class Tcp
    {
        private static readonly Regex Seq = new Regex(@"seq (\d+)(?::(\d+))?");
        private static readonly Regex Ack = new Regex(@"ack (\d+)");
        private static readonly Regex Win = new Regex(@"win (\d+)");
        private static readonly Regex Opts = new Regex(@"options \[([^\]]*)\]");
        private static readonly Regex Len = new Regex(@"length (\d+)");

        public static IEnumerable<DecodedSection> Decode(PacketRecord p, List<SymbolLegend> legend)
        {
            var info = p.Info ?? "";
            var ip = new DecodedSection(p.EtherType == "IPv6" ? "IPv6" : "IPv4",
                new DecodedField("Source", p.SrcIp),
                new DecodedField("Destination", p.DstIp),
                new DecodedField("Protocol", "TCP (6)"));
            yield return ip;

            var tcp = new DecodedSection("TCP");
            var app = RealtimeParser.TcpAppName(p.SrcPort, p.DstPort);
            tcp.Fields.Add(new DecodedField("Ports", $"{p.SrcPort}{Svc(p.SrcPort)} → {p.DstPort}{Svc(p.DstPort)}"));

            var f = p.TcpFlags;
            var tone = f.HasFlag(TcpFlags.RST) ? FieldTone.Bad : f.HasFlag(TcpFlags.SYN) && !f.HasFlag(TcpFlags.ACK) ? FieldTone.Warn : FieldTone.Good;
            tcp.Fields.Add(new DecodedField("Flags", f == TcpFlags.None ? "none" : string.Join(", ", FilterRule.FlagList(f)), tone));

            var seq = Seq.Match(info);
            if (seq.Success) tcp.Fields.Add(new DecodedField("Sequence", seq.Groups[2].Success ? $"{seq.Groups[1].Value}:{seq.Groups[2].Value}" : seq.Groups[1].Value));
            var ack = Ack.Match(info);
            if (ack.Success) tcp.Fields.Add(new DecodedField("Acknowledges", ack.Groups[1].Value));
            var win = Win.Match(info);
            if (win.Success) tcp.Fields.Add(new DecodedField("Window", win.Groups[1].Value));

            var opts = Opts.Match(info);
            if (opts.Success)
            {
                var o = opts.Groups[1].Value;
                tcp.Fields.Add(new DecodedField("Options", string.Join(", ", o.Split(',').Where(x => x.Trim() != "nop").Select(x => x.Trim()))));
                var mss = Regex.Match(o, @"mss (\d+)");
                if (mss.Success)
                {
                    int m = int.Parse(mss.Groups[1].Value, CultureInfo.InvariantCulture);
                    tcp.Fields.Add(new DecodedField("MSS", m + (m < 1460 ? " (below 1460: VPN, tunnel or MSS clamping in the path?)" : ""), m < 1460 ? FieldTone.Warn : FieldTone.Normal));
                }
                var ws = Regex.Match(o, @"wscale (\d+)");
                if (ws.Success)
                {
                    int w = int.Parse(ws.Groups[1].Value, CultureInfo.InvariantCulture);
                    tcp.Fields.Add(new DecodedField("Window scale", $"{w} → ×{1 << Math.Min(w, 14)}"));
                    legend.Add(new SymbolLegend("wscale " + w, $"window multiplier ×{1 << Math.Min(w, 14)} for this direction"));
                }
                if (o.Contains("sackOK"))
                {
                    tcp.Fields.Add(new DecodedField("SACK", "offered (sackOK); used only if both ends offer it", FieldTone.Good));
                    legend.Add(new SymbolLegend("sackOK", "selective acknowledgement offered"));
                }
            }

            var len = Len.Matches(info).Cast<Match>().LastOrDefault();
            if (len != null) tcp.Fields.Add(new DecodedField("Payload", len.Groups[1].Value + " bytes"));

            // Handshake reading, straight from "Troubleshoot TCP with pktmon".
            p.Title = $"TCP · {(f == TcpFlags.None ? "no flags" : string.Join(", ", FilterRule.FlagList(f)))}" + (app != null ? " · " + app : "");
            if (f.HasFlag(TcpFlags.SYN) && !f.HasFlag(TcpFlags.ACK))
            {
                p.Title = "TCP handshake 1 of 3 · SYN" + (app != null ? " · " + app : "");
                if (f.HasFlag(TcpFlags.ECE) && f.HasFlag(TcpFlags.CWR))
                    tcp.Fields.Add(new DecodedField("ECN", "offered (SYN carries ECE + CWR)"));
            }
            else if (f.HasFlag(TcpFlags.SYN) && f.HasFlag(TcpFlags.ACK))
            {
                p.Title = "TCP handshake 2 of 3 · SYN, ACK" + (app != null ? " · " + app : "");
                if (f.HasFlag(TcpFlags.ECE)) tcp.Fields.Add(new DecodedField("ECN", "agreed (SYN,ACK carries ECE)", FieldTone.Good));
            }
            else if (f.HasFlag(TcpFlags.RST))
                tcp.Fields.Add(new DecodedField("Session", "reset: port closed, firewall reject, or aborted connection", FieldTone.Bad));
            else if (f == TcpFlags.ACK && len != null && len.Groups[1].Value == "0")
                tcp.Fields.Add(new DecodedField("Note", "Bare ACK. If this follows a SYN,ACK, it's the 3rd handshake packet, and it proves the handshake finished."));

            yield return tcp;

            // Legend for the Flags [..] field.
            var fm = Regex.Match(info, @"Flags \[([^\]]*)\]");
            if (fm.Success)
            {
                var chars = fm.Groups[1].Value;
                foreach (var c in chars.Distinct())
                {
                    switch (c)
                    {
                        case 'S': legend.Add(new SymbolLegend("S", "SYN: opening, carries the initial sequence number")); break;
                        case '.': legend.Add(new SymbolLegend(".", "ACK: always shown as a dot, never as A")); break;
                        case 'P': legend.Add(new SymbolLegend("P", "PSH: deliver to the application now")); break;
                        case 'F': legend.Add(new SymbolLegend("F", "FIN: sender is done sending")); break;
                        case 'R': legend.Add(new SymbolLegend("R", "RST: connection refused or aborted")); break;
                        case 'U': legend.Add(new SymbolLegend("U", "URG: urgent pointer is valid")); break;
                        case 'E': legend.Add(new SymbolLegend("E", "ECE: ECN echo")); break;
                        case 'W': legend.Add(new SymbolLegend("W", "CWR: congestion window reduced")); break;
                    }
                }
                if (chars.Contains("S") && !chars.Contains(".")) legend.Add(new SymbolLegend("no .", "no ACK, which is only correct on handshake packet 1"));
                if (chars == ".") legend.Add(new SymbolLegend("[.]", "ACK alone: the packet people forget to look for"));
            }
            if (win.Success && !opts.Success) legend.Add(new SymbolLegend("win " + win.Groups[1].Value, "multiply by the wscale this side announced in its SYN"));
        }

        private static string Svc(int? port)
        {
            var n = RealtimeParser.TcpAppName(port, null);
            return n == null ? "" : $" ({n.ToLowerInvariant()})";
        }
    }

    internal static class Dns
    {
        // 47182+ [1au] A? app-gw.contoso.local. (58)
        // 47182* 1/0/1 A 10.30.14.98 (107)
        // 47182 NXDomain* 0/1/0 (120)
        private static readonly Regex Head = new Regex(@"^(?<id>\d+)(?<flags>[+*\-$|]*)\s*(?<rest>.*)$");
        private static readonly Regex Question = new Regex(@"(?:\[(?<au>\d+)au\]\s*)?(?<type>[A-Za-z0-9]+)\?\s+(?<name>\S+)");
        private static readonly Regex Counts = new Regex(@"(?<an>\d+)/(?<ns>\d+)/(?<ar>\d+)");
        private static readonly Regex Size = new Regex(@"\((\d+)\)\s*$");
        private static readonly string[] Rcodes = { "FormErr", "ServFail", "NXDomain", "NotImp", "Refused", "YXDomain", "YXRRSet", "NXRRSet", "NotAuth", "NotZone", "BadVers" };

        public static IEnumerable<DecodedSection> Decode(PacketRecord p, List<SymbolLegend> legend)
        {
            yield return PacketDecoder.IpSection(p, "UDP");

            var info = p.Info ?? "";
            var m = Head.Match(info);
            if (!m.Success)
            {
                yield return new DecodedSection("DNS", new DecodedField("Text", info));
                yield break;
            }
            var id = m.Groups["id"].Value;
            var flags = m.Groups["flags"].Value;
            var rest = m.Groups["rest"].Value;
            var s = new DecodedSection("DNS");
            var q = Question.Match(rest);
            bool isQuery = q.Success && !Counts.IsMatch(rest.Substring(0, q.Index));

            // The rcode word may be attached to the flags ("NXDomain*").
            var rcode = Rcodes.FirstOrDefault(r => rest.StartsWith(r, StringComparison.Ordinal));
            if (rcode != null)
            {
                var after = rest.Substring(rcode.Length);
                var extra = new string(after.TakeWhile(c => "+*-$|".IndexOf(c) >= 0).ToArray());
                flags += extra;
                rest = after.Substring(extra.Length).Trim();
            }

            if (isQuery)
            {
                p.Title = $"DNS query · {q.Groups["type"].Value} {q.Groups["name"].Value.TrimEnd('.')}";
                s.Fields.Add(new DecodedField("Type", "Standard query"));
                s.Fields.Add(new DecodedField("Question", $"{q.Groups["type"].Value} {q.Groups["name"].Value.TrimEnd('.')}"));
                s.Fields.Add(new DecodedField("Query id", id));
                s.Fields.Add(new DecodedField("Recursion", flags.Contains("+") ? "desired" : "not requested", flags.Contains("+") ? FieldTone.Good : FieldTone.Normal));
                if (q.Groups["au"].Success) s.Fields.Add(new DecodedField("Additional", q.Groups["au"].Value + " (OPT / EDNS0)"));
                legend.Add(new SymbolLegend("?", "QR = 0, so this is a question"));
                if (flags.Contains("+")) legend.Add(new SymbolLegend("+", "RD set: recursion desired"));
                if (q.Groups["au"].Success) legend.Add(new SymbolLegend($"[{q.Groups["au"].Value}au]", $"{q.Groups["au"].Value} additional record (EDNS0)"));
            }
            else
            {
                var c = Counts.Match(rest);
                var answers = c.Success ? rest.Substring(c.Index + c.Length) : rest;
                answers = Size.Replace(answers, "").Trim().TrimStart(',').Trim();
                p.Title = "DNS response" + (rcode != null ? " · " + rcode : answers.Length > 0 ? " · " + First(answers) : "");
                s.Fields.Add(new DecodedField("Type", "Response"));
                s.Fields.Add(new DecodedField("Query id", id));
                if (rcode != null) s.Fields.Add(new DecodedField("Result", rcode, FieldTone.Bad));
                else s.Fields.Add(new DecodedField("Result", "NoError", FieldTone.Good));
                if (answers.Length > 0) s.Fields.Add(new DecodedField("Answer", answers));
                if (c.Success) s.Fields.Add(new DecodedField("Counts", $"{c.Groups["an"].Value} answer / {c.Groups["ns"].Value} auth / {c.Groups["ar"].Value} addl"));
                var fl = new List<string>();
                if (flags.Contains("*")) fl.Add("authoritative");
                fl.Add(flags.Contains("-") ? "recursion NOT available" : "recursion available");
                if (flags.Contains("$")) fl.Add("DNSSEC validated (AD)");
                if (flags.Contains("|")) fl.Add("truncated (TC)");
                s.Fields.Add(new DecodedField("Flags", string.Join(", ", fl), flags.Contains("-") ? FieldTone.Warn : FieldTone.Normal));
                legend.Add(new SymbolLegend("no ?", "QR = 1, so this is a reply"));
                if (flags.Contains("*")) legend.Add(new SymbolLegend("*", "AA set: authoritative answer from the zone's server"));
                legend.Add(flags.Contains("-") ? new SymbolLegend("-", "RA clear: server can't recurse") : new SymbolLegend("no -", "RA set: recursion available"));
                if (flags.Contains("$")) legend.Add(new SymbolLegend("$", "AD set: DNSSEC-validated answer"));
                if (flags.Contains("|")) legend.Add(new SymbolLegend("|", "TC set: truncated, the client should retry over TCP"));
                if (c.Success) legend.Add(new SymbolLegend(c.Value, "answers / authority / additional"));
            }
            var size = Size.Match(info);
            if (size.Success)
            {
                s.Fields.Add(new DecodedField("DNS length", size.Groups[1].Value + " bytes"));
                legend.Add(new SymbolLegend($"({size.Groups[1].Value})", "DNS header + data length"));
            }
            yield return s;
        }

        private static string First(string answers)
        {
            var first = answers.Split(',')[0].Trim();
            return first.Length > 60 ? first.Substring(0, 60) + "…" : first;
        }
    }

    internal static class Icmp
    {
        public static IEnumerable<DecodedSection> Decode(PacketRecord p, List<SymbolLegend> legend)
        {
            var ip = new DecodedSection(p.Protocol == "ICMPv6" ? "IPv6" : "IPv4",
                new DecodedField("Source", p.SrcIp),
                new DecodedField("Destination", p.DstIp),
                new DecodedField("Protocol", p.Protocol == "ICMPv6" ? "ICMPv6 (58)" : "ICMP (1)"));
            yield return ip;

            var info = p.Info ?? "";
            var body = Regex.Replace(info, @"^ICMP6?,?\s*", "");
            var s = new DecodedSection(p.Protocol);
            var type = body.Split(',')[0].Trim();
            var tone = type.Contains("unreachable") || type.Contains("exceeded") ? FieldTone.Bad : FieldTone.Normal;
            s.Fields.Add(new DecodedField("Type", type, tone));
            p.Title = p.Protocol + " " + type;
            var id = Regex.Match(body, @"id (\S+?),");
            if (id.Success) s.Fields.Add(new DecodedField("Identifier", id.Groups[1].Value));
            var seq = Regex.Match(body, @"seq (\d+)");
            if (seq.Success) s.Fields.Add(new DecodedField("Sequence", seq.Groups[1].Value));
            var len = Regex.Match(body, @"length (\d+)");
            if (len.Success) s.Fields.Add(new DecodedField("Length", len.Groups[1].Value + " bytes"));
            if (type.Contains("echo request")) s.Fields.Add(new DecodedField("Expect", "an echo reply with the same id and seq"));
            if (type.Contains("time exceeded")) s.Fields.Add(new DecodedField("Meaning", "TTL hit zero: a routing loop, or traceroute at work", FieldTone.Warn));
            if (type.Contains("need to frag")) s.Fields.Add(new DecodedField("Meaning", "Path MTU is smaller than the packet (PMTUD)", FieldTone.Warn));
            yield return s;
        }
    }

    internal static class Arp
    {
        public static DecodedSection Decode(PacketRecord p, List<SymbolLegend> legend)
        {
            var info = p.Info ?? "";
            var s = new DecodedSection("ARP");
            var req = Regex.Match(info, @"Request who-has (\S+?)(?: \((\S+)\))? tell (\S+?),");
            var rep = Regex.Match(info, @"Reply (\S+) is-at (\S+?),");
            if (req.Success)
            {
                p.Title = $"ARP who-has {req.Groups[1].Value}";
                s.Fields.Add(new DecodedField("Operation", "Request (1)"));
                s.Fields.Add(new DecodedField("Looking for", req.Groups[1].Value));
                s.Fields.Add(new DecodedField("Asked by", req.Groups[3].Value));
                if (req.Groups[1].Value == req.Groups[3].Value)
                    s.Fields.Add(new DecodedField("Note", "Gratuitous ARP: announcing its own address (or checking for a duplicate)", FieldTone.Warn));
            }
            else if (rep.Success)
            {
                p.Title = $"ARP {rep.Groups[1].Value} is-at {rep.Groups[2].Value}";
                s.Fields.Add(new DecodedField("Operation", "Reply (2)"));
                s.Fields.Add(new DecodedField("Address", rep.Groups[1].Value));
                s.Fields.Add(new DecodedField("Is at", rep.Groups[2].Value.ToUpperInvariant().Replace(':', '-'), FieldTone.Good));
            }
            else s.Fields.Add(new DecodedField("Text", info));
            return s;
        }
    }

    /// <summary>CDP and LLDP. Real-time mode shows little; etl2txt --verbose carries the detail.</summary>
    internal static class Discovery
    {
        public static DecodedSection Decode(PacketRecord p, List<SymbolLegend> legend)
        {
            var all = string.Join("\n", p.RawLines.Skip(1));
            var s = new DecodedSection(p.Protocol);
            void Find(string label, params string[] patterns)
            {
                foreach (var pat in patterns)
                {
                    var m = Regex.Match(all, pat, RegexOptions.IgnoreCase);
                    if (m.Success) { s.Fields.Add(new DecodedField(label, m.Groups[1].Value.Trim().Trim('\'', '"'))); return; }
                }
            }
            if (p.Protocol == "CDP")
            {
                Find("Device", @"Device-ID[^']*'([^']+)'", @"Device-ID \(0x01\)[^:]*:\s*'?([^'\n]+)");
                Find("Port", @"Port-ID[^']*'([^']+)'", @"Port-ID \(0x03\)[^:]*:\s*'?([^'\n]+)");
                Find("Platform", @"Platform[^']*'([^']+)'");
                Find("Native VLAN", @"Native VLAN ID[^:]*:\s*(\d+)");
                Find("Address", @"Address[^:]*:\s*.*?IPv4 \(\d+\) (\S+)");
                Find("Software", @"Version String[^:]*:\s*(.+)");
            }
            else
            {
                Find("System name", @"System Name TLV[^:]*:\s*(.+)", @"System Name[^:]*:\s*(.+)");
                Find("Port", @"Port ID TLV[^:]*:\s*.*?:\s*(.+)", @"Port ID[^:]*:\s*(.+)");
                Find("Port description", @"Port Description TLV[^:]*:\s*(.+)", @"Port Description[^:]*:\s*(.+)");
                Find("Chassis", @"Chassis ID TLV[^:]*:\s*.*?:\s*(.+)", @"Chassis ID[^:]*:\s*(.+)");
                Find("VLAN", @"port vlan id \(PVID\):\s*(\d+)", @"PVID[^:]*:\s*(\d+)");
                Find("Management", @"Management Address[^:]*:\s*.*?:\s*(\S+)");
            }
            if (s.Fields.Count == 0)
            {
                s.Fields.Add(new DecodedField("Summary", p.Info));
                s.Fields.Add(new DecodedField("More detail", "Record mode, then Files → Convert to text (etl2txt --verbose) shows switch name and port.", FieldTone.Warn));
            }
            else
            {
                var dev = s.Fields.FirstOrDefault(f => f.Key == "Device" || f.Key == "System name");
                var port = s.Fields.FirstOrDefault(f => f.Key == "Port");
                p.Title = $"{p.Protocol} · {dev?.Value ?? "neighbour"}{(port != null ? " port " + port.Value : "")}";
            }
            return s;
        }
    }
}
