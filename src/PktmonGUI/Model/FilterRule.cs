using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace PktmonGUI.Model
{
    [Flags]
    public enum TcpFlags
    {
        None = 0,
        FIN = 1, SYN = 2, RST = 4, PSH = 8, ACK = 16, URG = 32, ECE = 64, CWR = 128,
    }

    /// <summary>
    /// One <c>pktmon filter add</c> line. Every field set on a rule must match (AND);
    /// separate rules are alternatives (OR). pktmon can't tell source from destination,
    /// and it has no ranges or negation.
    /// </summary>
    public sealed class FilterRule
    {
        public const int MaxRules = 32;

        public string Name { get; set; }

        public string Mac1 { get; set; }
        public string Mac2 { get; set; }
        public int? Vlan { get; set; }
        /// <summary>IPv4, IPv6, ARP or a number (decimal or 0x hex).</summary>
        public string EtherType { get; set; }
        public int? Dscp { get; set; }
        /// <summary>TCP, UDP, ICMP, ICMPv6 or an IP protocol number.</summary>
        public string Transport { get; set; }
        public TcpFlags TcpFlags { get; set; }
        public string Ip1 { get; set; }
        public string Ip2 { get; set; }
        public int? Port1 { get; set; }
        public int? Port2 { get; set; }
        public bool Heartbeat { get; set; }
        public bool Encap { get; set; }
        public int? EncapPort { get; set; }

        /// <summary>
        /// Friendly EtherType names shown in the builder. pktmon only knows IPv4, IPv6 and ARP
        /// by name, so everything else is emitted as its number.
        /// </summary>
        public static readonly IReadOnlyList<KeyValuePair<string, string>> KnownEtherTypes = new[]
        {
            new KeyValuePair<string, string>("IPv4", "IPv4"),
            new KeyValuePair<string, string>("IPv6", "IPv6"),
            new KeyValuePair<string, string>("ARP", "ARP"),
            new KeyValuePair<string, string>("LLDP", "0x88CC"),
            new KeyValuePair<string, string>("802.1X (EAPOL)", "0x888E"),
            new KeyValuePair<string, string>("VLAN (802.1Q)", "0x8100"),
            new KeyValuePair<string, string>("LACP / Slow protocols", "0x8809"),
            new KeyValuePair<string, string>("Ethernet flow control", "0x8808"),
            new KeyValuePair<string, string>("PTP", "0x88F7"),
            new KeyValuePair<string, string>("RoCE", "0x8915"),
        };

        public static readonly IReadOnlyList<string> KnownTransports = new[] { "TCP", "UDP", "ICMP", "ICMPv6" };

        [JsonIgnore]
        public bool IsTcp => string.Equals(Transport, "TCP", StringComparison.OrdinalIgnoreCase) || Transport == "6";

        [JsonIgnore]
        public bool IsEmpty =>
            Mac1 == null && Mac2 == null && Vlan == null && EtherType == null && Dscp == null &&
            Transport == null && Ip1 == null && Ip2 == null && Port1 == null && Port2 == null &&
            !Heartbeat && !Encap;

        public FilterRule Clone() => (FilterRule)MemberwiseClone();

        /// <summary>Arguments after <c>pktmon filter add</c>, in pktmon's documented order.</summary>
        public IEnumerable<string> ToArgs()
        {
            if (!string.IsNullOrWhiteSpace(Name)) yield return Name.Trim();
            if (Mac1 != null) { yield return "-m"; yield return NormalizeMac(Mac1); if (Mac2 != null) yield return NormalizeMac(Mac2); }
            if (Vlan.HasValue) { yield return "-v"; yield return Vlan.Value.ToString(CultureInfo.InvariantCulture); }
            if (EtherType != null) { yield return "-d"; yield return EtherType; }
            if (Dscp.HasValue) { yield return "--dscp"; yield return Dscp.Value.ToString(CultureInfo.InvariantCulture); }
            if (Transport != null)
            {
                yield return "-t";
                yield return Transport;
                if (IsTcp)
                    foreach (var f in FlagList(TcpFlags)) yield return f;
            }
            if (Ip1 != null) { yield return "-i"; yield return Ip1; if (Ip2 != null) yield return Ip2; }
            if (Port1.HasValue) { yield return "-p"; yield return Port1.Value.ToString(CultureInfo.InvariantCulture); if (Port2.HasValue) yield return Port2.Value.ToString(CultureInfo.InvariantCulture); }
            if (Heartbeat) yield return "-b";
            if (Encap) { yield return "-e"; if (EncapPort.HasValue) yield return EncapPort.Value.ToString(CultureInfo.InvariantCulture); }
        }

        /// <summary>The arguments without the name, e.g. <c>-t UDP -p 53</c>. Used in presets and chips.</summary>
        [JsonIgnore]
        public string ArgsSummary
        {
            get
            {
                var c = Clone();
                c.Name = null;
                var s = string.Join(" ", c.ToArgs().Select(Pktmon.PktmonCommand.QuoteArg));
                return s.Length == 0 ? "(matches everything)" : s;
            }
        }

        /// <summary>
        /// What the rule matches, as a comparable string. The name is left out, and so is the order of a
        /// pair (pktmon reads <c>-i A B</c> and <c>-i B A</c> alike): equal keys are the same filter.
        /// </summary>
        [JsonIgnore]
        public string MatchKey
        {
            get
            {
                var c = Clone();
                c.Name = null;
                if (c.Mac1 != null && c.Mac2 != null && string.CompareOrdinal(NormalizeMac(c.Mac1), NormalizeMac(c.Mac2)) > 0) (c.Mac1, c.Mac2) = (c.Mac2, c.Mac1);
                if (c.Ip1 != null && c.Ip2 != null && string.Compare(c.Ip1, c.Ip2, StringComparison.OrdinalIgnoreCase) > 0) (c.Ip1, c.Ip2) = (c.Ip2, c.Ip1);
                if (c.Port2 < c.Port1) (c.Port1, c.Port2) = (c.Port2, c.Port1);
                return string.Join(" ", c.ToArgs()).ToUpperInvariant();
            }
        }

        /// <summary>Compact label like <c>UDP/53</c> or <c>TCP/443 SYN</c>.</summary>
        [JsonIgnore]
        public string ShortLabel
        {
            get
            {
                var parts = new List<string>();
                if (Transport != null)
                {
                    var t = Transport.ToUpperInvariant();
                    if (Port1.HasValue) t += "/" + Port1 + (Port2.HasValue ? "," + Port2 : "");
                    if (IsTcp && TcpFlags != TcpFlags.None) t += " " + string.Join(",", FlagList(TcpFlags));
                    parts.Add(t);
                }
                else if (Port1.HasValue) parts.Add("port " + Port1 + (Port2.HasValue ? "," + Port2 : ""));
                if (Ip1 != null) parts.Add(Ip1 + (Ip2 != null ? "↔" + Ip2 : ""));
                if (EtherType != null)
                    parts.Add(KnownEtherTypes.FirstOrDefault(k => string.Equals(k.Value, EtherType, StringComparison.OrdinalIgnoreCase)).Key ?? EtherType);
                if (Mac1 != null) parts.Add(Mac1);
                if (Vlan.HasValue) parts.Add("VLAN " + Vlan);
                if (Dscp.HasValue) parts.Add("DSCP " + Dscp);
                if (Heartbeat) parts.Add("heartbeat");
                if (Encap) parts.Add("+encap");
                return parts.Count == 0 ? "everything" : string.Join(" · ", parts);
            }
        }

        public static IEnumerable<string> FlagList(TcpFlags flags) =>
            Enum.GetValues(typeof(TcpFlags)).Cast<TcpFlags>()
                .Where(f => f != TcpFlags.None && flags.HasFlag(f))
                .Select(f => f.ToString());

        /// <summary>
        /// Plain-English reading of the rule, e.g. "it is to or from 10.30.14.10 and is UDP and uses port 53".
        /// </summary>
        public string Describe()
        {
            var p = new List<string>();
            if (Ip1 != null) p.Add(Ip2 == null ? $"it is to or from {Ip1}" : $"it is between {Ip1} and {Ip2}");
            if (Mac1 != null) p.Add(Mac2 == null ? $"its MAC is {Mac1}" : $"it is between MACs {Mac1} and {Mac2}");
            if (Vlan.HasValue) p.Add($"it is tagged VLAN {Vlan}");
            if (EtherType != null)
                p.Add($"its EtherType is {KnownEtherTypes.FirstOrDefault(k => string.Equals(k.Value, EtherType, StringComparison.OrdinalIgnoreCase)).Key ?? EtherType}");
            if (Dscp.HasValue) p.Add($"its DSCP is {Dscp}");
            if (Transport != null) p.Add($"it is {Transport}");
            if (IsTcp && TcpFlags != TcpFlags.None)
            {
                var fl = FlagList(TcpFlags).ToList();
                p.Add(fl.Count == 1 ? $"carries {fl[0]}" : $"carries any of {string.Join(", ", fl)}");
            }
            if (Port1.HasValue) p.Add(Port2 == null ? $"uses port {Port1}" : $"uses ports {Port1} and {Port2}");
            if (Heartbeat) p.Add("it is a cluster heartbeat (UDP 3343)");
            if (Encap) p.Add("inner or outer headers match (VXLAN/GRE/NVGRE/IP-in-IP)");
            return p.Count == 0 ? "it is any packet" : string.Join(" and ", p);
        }

        // ---- Validation -------------------------------------------------------

        public IEnumerable<string> Validate()
        {
            if (Name != null && Name.IndexOf('"') >= 0) yield return "Name cannot contain double quotes.";
            if (Mac1 != null && !IsMac(Mac1)) yield return $"'{Mac1}' is not a MAC address (xx-xx-xx-xx-xx-xx).";
            if (Mac2 != null && !IsMac(Mac2)) yield return $"'{Mac2}' is not a MAC address.";
            if (Mac2 != null && Mac1 == null) yield return "Set the first MAC before the second.";
            if (Vlan.HasValue && (Vlan < 0 || Vlan > 4095)) yield return "VLAN ID must be 0–4095.";
            if (Dscp.HasValue && (Dscp < 0 || Dscp > 63)) yield return "DSCP must be 0–63.";
            if (EtherType != null && !IsEtherType(EtherType)) yield return $"'{EtherType}' is not IPv4, IPv6, ARP or a number.";
            if (Transport != null && !IsTransport(Transport)) yield return $"'{Transport}' is not TCP, UDP, ICMP, ICMPv6 or a protocol number 0–255.";
            if (TcpFlags != TcpFlags.None && !IsTcp) yield return "TCP flags need Transport = TCP.";
            if (Ip1 != null && !IsIpOrCidr(Ip1)) yield return $"'{Ip1}' is not an IP address or CIDR subnet.";
            if (Ip2 != null && !IsIpOrCidr(Ip2)) yield return $"'{Ip2}' is not an IP address or CIDR subnet.";
            if (Ip2 != null && Ip1 == null) yield return "Set the first IP before the second.";
            if (Port1.HasValue && (Port1 < 0 || Port1 > 65535)) yield return "Port must be 0–65535.";
            if (Port2.HasValue && (Port2 < 0 || Port2 > 65535)) yield return "Second port must be 0–65535.";
            if (Port2.HasValue && !Port1.HasValue) yield return "Set the first port before the second.";
            if ((Port1.HasValue) && Transport != null && !IsTcp && !IsUdp(Transport))
                yield return "Ports only exist on TCP and UDP.";
            if (EncapPort.HasValue && !Encap) yield return "Encapsulation port needs encapsulation enabled.";
            if (EncapPort.HasValue && (EncapPort < 1 || EncapPort > 65535)) yield return "VXLAN port must be 1–65535.";
        }

        private static bool IsUdp(string t) => string.Equals(t, "UDP", StringComparison.OrdinalIgnoreCase) || t == "17";

        private static readonly Regex MacRx = new Regex(@"^[0-9A-Fa-f]{2}([-:]?)[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$");
        public static bool IsMac(string s) => s != null && MacRx.IsMatch(s.Trim());

        public static string NormalizeMac(string s)
        {
            var hex = new string(s.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
            if (hex.Length != 12) return s;
            return string.Join("-", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
        }

        public static bool IsEtherType(string s)
        {
            if (s == null) return false;
            if (new[] { "IPv4", "IPv6", "ARP" }.Any(n => string.Equals(n, s, StringComparison.OrdinalIgnoreCase))) return true;
            return TryParseNumber(s, out var v) && v >= 0 && v <= 0xFFFF;
        }

        public static bool IsTransport(string s)
        {
            if (s == null) return false;
            if (KnownTransports.Any(n => string.Equals(n, s, StringComparison.OrdinalIgnoreCase))) return true;
            return TryParseNumber(s, out var v) && v >= 0 && v <= 255;
        }

        public static bool IsIpOrCidr(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return false;
            var parts = s.Trim().Split('/');
            if (parts.Length > 2) return false;
            if (!IPAddress.TryParse(parts[0], out var ip)) return false;
            if (parts.Length == 1) return true;
            int max = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
            return int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var len) && len >= 0 && len <= max;
        }

        public static bool TryParseNumber(string s, out long value)
        {
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return long.TryParse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
            return long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out value);
        }

        // ---- Parsing (the reverse of ToArgs) ------------------------------------------

        /// <summary>
        /// Every spelling <c>pktmon filter add help</c> documents, mapped to the short form
        /// <see cref="ToArgs"/> writes.
        /// </summary>
        internal static readonly IReadOnlyDictionary<string, string> OptionAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["-m"] = "-m", ["--mac"] = "-m", ["--mac-address"] = "-m",
            ["-v"] = "-v", ["--vlan"] = "-v",
            ["-d"] = "-d", ["--data-link"] = "-d", ["--data-link-protocol"] = "-d", ["--ethertype"] = "-d",
            ["--dscp"] = "--dscp",
            ["-t"] = "-t", ["--transport"] = "-t", ["--transport-protocol"] = "-t", ["--ip-protocol"] = "-t",
            ["-i"] = "-i", ["--ip"] = "-i", ["--ip-address"] = "-i",
            ["-p"] = "-p", ["--port"] = "-p",
            ["-b"] = "-b", ["--heartbeat"] = "-b",
            ["-e"] = "-e", ["--encap"] = "-e",
        };

        /// <summary>Parses a rule written as for <c>pktmon filter add</c>, e.g. <c>DNS -t UDP -p 53</c>.</summary>
        /// <exception cref="FormatException">The text isn't a valid rule.</exception>
        public static FilterRule Parse(string text)
        {
            if (!TryParse(text, out var rule, out var error)) throw new FormatException(error);
            return rule;
        }

        /// <summary>
        /// Parses a rule written as for <c>pktmon filter add</c>, with or without that prefix:
        /// an optional name first, then options in any order, short or long form.
        /// </summary>
        public static bool TryParse(string text, out FilterRule rule, out string error) =>
            TryParse(ArgSplitter.Split(text), out rule, out error);

        public static bool TryParse(IReadOnlyList<string> args, out FilterRule rule, out string error)
        {
            rule = null;
            var a = args.ToList();
            if (a.Count > 0 && (string.Equals(a[0], "pktmon", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(a[0], "pktmon.exe", StringComparison.OrdinalIgnoreCase)))
                a.RemoveAt(0);
            if (a.Count >= 2 && string.Equals(a[0], "filter", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(a[1], "add", StringComparison.OrdinalIgnoreCase))
                a.RemoveRange(0, 2);

            var r = new FilterRule();
            var seen = new HashSet<string>();
            int i = 0;
            if (a.Count > 0 && !a[0].StartsWith("-", StringComparison.Ordinal)) r.Name = a[i++];

            while (i < a.Count)
            {
                var token = a[i++];
                if (!OptionAliases.TryGetValue(token, out var opt))
                {
                    error = token.StartsWith("-", StringComparison.Ordinal)
                        ? $"'{token}' isn't a pktmon filter option."
                        : $"Unexpected '{token}': only the name may come before the options.";
                    return false;
                }
                if (!seen.Add(opt)) { error = $"'{token}' is given twice."; return false; }

                // Options with no value.
                if (opt == "-b") { r.Heartbeat = true; continue; }
                if (opt == "-e")
                {
                    r.Encap = true;
                    if (i < a.Count && TryInt(a[i], out var ep)) { r.EncapPort = ep; i++; }
                    continue;
                }

                if (i >= a.Count || OptionAliases.ContainsKey(a[i])) { error = $"'{token}' needs a value."; return false; }
                var value = a[i++];
                switch (opt)
                {
                    case "-m":
                        r.Mac1 = value;
                        if (i < a.Count && IsMac(a[i])) r.Mac2 = a[i++];
                        break;
                    case "-v":
                        if (!TryInt(value, out var vlan)) { error = $"'{value}' isn't a VLAN ID."; return false; }
                        r.Vlan = vlan;
                        break;
                    case "-d":
                        r.EtherType = new[] { "IPv4", "IPv6", "ARP" }.FirstOrDefault(n => string.Equals(n, value, StringComparison.OrdinalIgnoreCase)) ?? value;
                        break;
                    case "--dscp":
                        if (!TryInt(value, out var dscp)) { error = $"'{value}' isn't a DSCP value."; return false; }
                        r.Dscp = dscp;
                        break;
                    case "-t":
                        r.Transport = KnownTransports.FirstOrDefault(n => string.Equals(n, value, StringComparison.OrdinalIgnoreCase)) ?? value;
                        if (r.IsTcp)
                            while (i < a.Count && Enum.TryParse<TcpFlags>(a[i], true, out var flag) && flag != TcpFlags.None &&
                                   Enum.GetNames(typeof(TcpFlags)).Any(n => string.Equals(n, a[i], StringComparison.OrdinalIgnoreCase)))
                            {
                                r.TcpFlags |= flag;
                                i++;
                            }
                        break;
                    case "-i":
                        r.Ip1 = value;
                        if (i < a.Count && IsIpOrCidr(a[i])) r.Ip2 = a[i++];
                        break;
                    case "-p":
                        if (!TryInt(value, out var port)) { error = $"'{value}' isn't a port number."; return false; }
                        r.Port1 = port;
                        if (i < a.Count && TryInt(a[i], out var port2)) { r.Port2 = port2; i++; }
                        break;
                }
            }

            error = r.Validate().FirstOrDefault();
            if (error != null) return false;
            rule = r;
            return true;
        }

        private static bool TryInt(string s, out int value)
        {
            value = 0;
            if (!TryParseNumber(s, out var v) || v > int.MaxValue) return false;
            value = (int)v;
            return true;
        }
    }
}
