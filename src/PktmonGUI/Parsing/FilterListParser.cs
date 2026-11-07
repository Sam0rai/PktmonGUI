using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using PktmonGUI.Model;

namespace PktmonGUI.Parsing
{
    /// <summary>
    /// Parses the table printed by <c>pktmon filter list</c> (there's no JSON form):
    /// <code>
    ///  # Name        EtherType Protocol  IP Address   Port
    ///  - ----        --------- --------  ----------   ----
    ///  1 DNS to DC             UDP       10.30.14.10    53
    ///  2 HTTPS setup           TCP SYN                 443
    /// </code>
    /// Columns only appear when some filter uses them, so they're located from the dash
    /// row under the header rather than assumed. Each row is mapped back to a
    /// <see cref="FilterRule"/> so it can be replayed with <c>filter add</c> later.
    /// </summary>
    public static class FilterListParser
    {
        private enum Col { Index, Name, Mac, Vlan, EtherType, Dscp, Transport, Ip, Port, Heartbeat, Encap, Unknown }

        private sealed class Column
        {
            public Col Kind;
            public string Header;
            public int Start;
            public int End; // exclusive; int.MaxValue for the last
        }

        public static List<ExistingFilter> Parse(string text)
        {
            var result = new List<ExistingFilter>();
            var lines = (text ?? "").Replace("\r", "").Split('\n');

            int dashRow = Array.FindIndex(lines, l => Regex.IsMatch(l, @"^\s*-+(\s+-+)+\s*$"));
            if (dashRow < 1) return result;

            var columns = LocateColumns(lines[dashRow - 1], lines[dashRow]);
            if (columns.Count == 0) return result;

            ExistingFilter current = null;
            for (int i = dashRow + 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (line.Trim().Length == 0) continue;
                var cells = Slice(line, columns);
                var idxCell = cells.FirstOrDefault(c => c.Key.Kind == Col.Index).Value;

                if (!string.IsNullOrEmpty(idxCell) && int.TryParse(idxCell, NumberStyles.None, CultureInfo.InvariantCulture, out var idx))
                {
                    current = new ExistingFilter { Index = idx, Rule = new FilterRule(), RawText = line.TrimEnd() };
                    result.Add(current);
                }
                else if (current != null)
                {
                    // Continuation row: the second IP/port/MAC of a two-value filter.
                    current.RawText += Environment.NewLine + line.TrimEnd();
                }
                else continue;

                foreach (var kv in cells)
                    if (!string.IsNullOrWhiteSpace(kv.Value))
                        Apply(current, kv.Key, kv.Value.Trim());
            }
            return result;
        }

        private static List<Column> LocateColumns(string header, string dashes)
        {
            var cols = new List<Column>();
            foreach (Match m in Regex.Matches(dashes, @"-+"))
                cols.Add(new Column { Start = m.Index, End = m.Index + m.Length });

            // The header text of a column runs from its dashes to the next column's dashes
            // ("IP Address" can be wider than "--").
            for (int i = 0; i < cols.Count; i++)
            {
                int hs = Math.Min(cols[i].Start, header.Length);
                int he = Math.Min(i + 1 < cols.Count ? cols[i + 1].Start : header.Length, header.Length);
                cols[i].Header = he > hs ? header.Substring(hs, he - hs).Trim() : "";
                cols[i].Kind = Classify(cols[i].Header, i);
            }
            return cols;
        }

        private static Col Classify(string h, int position)
        {
            var s = h.ToLowerInvariant();
            if (s == "#" || s == "id" || s == "index" || (position == 0 && s.Length <= 2)) return Col.Index;
            if (s.StartsWith("name")) return Col.Name;
            if (s.Contains("mac")) return Col.Mac;
            if (s.Contains("vlan")) return Col.Vlan;
            if (s.Contains("ethertype") || s.Contains("data link") || s.Contains("datalink")) return Col.EtherType;
            if (s.Contains("dscp")) return Col.Dscp;
            if (s.Contains("protocol") || s.Contains("transport")) return Col.Transport;
            if (s.StartsWith("ip")) return Col.Ip;
            if (s.StartsWith("port")) return Col.Port;
            if (s.Contains("heartbeat")) return Col.Heartbeat;
            if (s.Contains("encap")) return Col.Encap;
            return Col.Unknown;
        }

        /// <summary>
        /// Splits the row into runs of text separated by two or more spaces (values such as
        /// "TCP SYN" or "DNS to DC" contain single spaces) and gives each run to the column
        /// its span overlaps most, or else the nearest one. That handles left-aligned text
        /// wider than its dashes and right-aligned numbers that start left of them.
        /// </summary>
        private static List<KeyValuePair<Column, string>> Slice(string line, List<Column> cols)
        {
            var values = cols.ToDictionary(c => c, c => new List<string>());

            // The row number is separated from the name by a single space; peel it off first.
            var indexCol = cols.FirstOrDefault(c => c.Kind == Col.Index);
            var lead = Regex.Match(line, @"^\s*(\d+)(?=\s|$)");
            if (indexCol != null && lead.Success)
            {
                values[indexCol].Add(lead.Groups[1].Value);
                line = new string(' ', lead.Length) + line.Substring(lead.Length);
            }

            foreach (var run in Runs(line, cols))
            {
                int s = run.Index, e = run.Index + run.Length;
                Column best = null;
                int bestScore = int.MinValue;
                foreach (var c in cols)
                {
                    int overlap = Math.Min(e, c.End) - Math.Max(s, c.Start);
                    int score = overlap > 0 ? overlap * 1000 : -Math.Min(Math.Abs(s - c.End), Math.Abs(c.Start - e));
                    if (score > bestScore) { bestScore = score; best = c; }
                }
                values[best].Add(run.Value);
            }
            return cols.Select(c => new KeyValuePair<Column, string>(c, string.Join(" ", values[c]))).ToList();
        }

        /// <summary>
        /// The runs of <paramref name="line"/>, also split where a word starts exactly at a column:
        /// pktmon pads the Name column to the longest name plus one space, so that name and the
        /// next value ("SenseNdrTest2 UDP") are only a single space apart.
        /// </summary>
        private static IEnumerable<(int Index, int Length, string Value)> Runs(string line, List<Column> cols)
        {
            foreach (Match run in Regex.Matches(line, @"\S+(?: \S+)*"))
            {
                int start = run.Index, end = run.Index;
                foreach (Match word in Regex.Matches(run.Value, @"\S+"))
                {
                    int ws = run.Index + word.Index;
                    if (ws > start && cols.Any(c => c.Start == ws))
                    {
                        yield return (start, end - start, line.Substring(start, end - start));
                        start = ws;
                    }
                    end = ws + word.Length;
                }
                yield return (start, end - start, line.Substring(start, end - start));
            }
        }

        private static void Apply(ExistingFilter f, Column col, string v)
        {
            var r = f.Rule;
            switch (col.Kind)
            {
                case Col.Index: break;
                case Col.Name: r.Name = r.Name == null ? v : r.Name + " " + v; break;
                case Col.Mac:
                    foreach (var m in v.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                        if (r.Mac1 == null) r.Mac1 = m; else if (r.Mac2 == null) r.Mac2 = m;
                    break;
                case Col.Vlan:
                    if (int.TryParse(v, out var vlan)) r.Vlan = vlan; else f.FullyParsed = false;
                    break;
                case Col.EtherType: r.EtherType = NormalizeEtherType(v); break;
                case Col.Dscp:
                    if (int.TryParse(v, out var dscp)) r.Dscp = dscp; else f.FullyParsed = false;
                    break;
                case Col.Transport:
                    // pktmon prints flags as "TCP (FIN SYN ACK)".
                    var parts = v.Split(new[] { ' ', ',', '(', ')' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 0) break;
                    r.Transport = NormalizeTransport(parts[0]);
                    foreach (var flag in parts.Skip(1))
                        if (Enum.TryParse<TcpFlags>(flag, true, out var tf)) r.TcpFlags |= tf;
                        else f.FullyParsed = false;
                    break;
                case Col.Ip:
                    foreach (var ip in v.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                        if (r.Ip1 == null) r.Ip1 = ip; else if (r.Ip2 == null) r.Ip2 = ip;
                    break;
                case Col.Port:
                    foreach (var p in v.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (!int.TryParse(p, out var port)) { f.FullyParsed = false; continue; }
                        if (r.Port1 == null) r.Port1 = port; else if (r.Port2 == null) r.Port2 = port;
                    }
                    break;
                case Col.Heartbeat:
                    if (IsYes(v)) r.Heartbeat = true;
                    break;
                case Col.Encap:
                    if (IsYes(v)) r.Encap = true;
                    else if (int.TryParse(v, out var ep)) { r.Encap = true; if (ep != 4789) r.EncapPort = ep; }
                    break;
                default:
                    f.FullyParsed = false;
                    break;
            }
        }

        private static bool IsYes(string v) =>
            v.Equals("yes", StringComparison.OrdinalIgnoreCase) || v.Equals("true", StringComparison.OrdinalIgnoreCase) ||
            v.Equals("on", StringComparison.OrdinalIgnoreCase) || v == "1" || v.Equals("enabled", StringComparison.OrdinalIgnoreCase);

        internal static string NormalizeEtherType(string v)
        {
            foreach (var n in new[] { "IPv4", "IPv6", "ARP" })
                if (v.Equals(n, StringComparison.OrdinalIgnoreCase)) return n;
            var known = FilterRule.KnownEtherTypes.FirstOrDefault(k => k.Key.StartsWith(v, StringComparison.OrdinalIgnoreCase));
            if (known.Value != null) return known.Value;
            if (FilterRule.TryParseNumber(v, out var num)) return "0x" + num.ToString("X4", CultureInfo.InvariantCulture);
            var paren = Regex.Match(v, @"0x[0-9A-Fa-f]+");
            return paren.Success ? paren.Value : v;
        }

        internal static string NormalizeTransport(string v)
        {
            foreach (var n in FilterRule.KnownTransports)
                if (v.Equals(n, StringComparison.OrdinalIgnoreCase)) return n;
            if (FilterRule.TryParseNumber(v, out var num))
            {
                switch (num)
                {
                    case 6: return "TCP";
                    case 17: return "UDP";
                    case 1: return "ICMP";
                    case 58: return "ICMPv6";
                    default: return num.ToString(CultureInfo.InvariantCulture);
                }
            }
            return v;
        }
    }
}
