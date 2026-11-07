using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using PktmonGUI.Model;

namespace PktmonGUI.Parsing
{
    /// <summary>
    /// Parses <c>pktmon counters --json</c>:
    /// <code>
    /// [ { "Group": "Intel(R) Ethernet ...", "Components": [ { "Name": "...", "Id": 15, "Counters": [
    ///     { "Name": "e1d68x64.sys", "Type": "Drops",
    ///       "Inbound":  { "Last Drop Reason": "Unsupported EtherType", "DirectionTag": "Rx", "Packets": 298, "Bytes": 250633 },
    ///       "Outbound": { "Last Drop Reason": "Not specified", "DirectionTag": "Tx", "Packets": 0, "Bytes": 0 } },
    ///     { "Name": "Upper", "Type": "Flows", "Inbound": {...}, "Outbound": {...} } ] } ] } ]
    /// </code>
    /// A filter driver reports a Flows counter for both its Upper and Lower edge. The same
    /// packets cross both, so flows take the busier edge rather than the sum. Drops are
    /// summed across the drivers that report them.
    /// </summary>
    public static class CountersParser
    {
        public const string NoReason = "Not specified";

        public static List<CounterRow> Parse(string output)
        {
            var text = (output ?? "").Trim();
            int start = text.IndexOfAny(new[] { '[', '{' });
            if (start >= 0)
            {
                try
                {
                    using (var doc = JsonDocument.Parse(text.Substring(start), new JsonDocumentOptions { AllowTrailingCommas = true }))
                    {
                        var rows = new List<CounterRow>();
                        Walk(doc.RootElement, null, rows);
                        return rows;
                    }
                }
                catch (JsonException) { }
            }
            return ParseText(text);
        }

        private static void Walk(JsonElement e, string group, List<CounterRow> rows)
        {
            if (e.ValueKind == JsonValueKind.Array)
            {
                foreach (var i in e.EnumerateArray()) Walk(i, group, rows);
                return;
            }
            if (e.ValueKind != JsonValueKind.Object) return;

            if (TryInt(e, "Id", out var id) && e.TryGetProperty("Name", out var nameEl) && nameEl.ValueKind == JsonValueKind.String)
            {
                var row = new CounterRow { ComponentId = id, ComponentName = nameEl.GetString(), Group = group };
                if (e.TryGetProperty("Counters", out var counters) && counters.ValueKind == JsonValueKind.Array)
                    foreach (var c in counters.EnumerateArray())
                        AddCounter(c, row);
                rows.Add(row);
                return;
            }

            var g = e.TryGetProperty("Group", out var gEl) && gEl.ValueKind == JsonValueKind.String ? gEl.GetString() : group;
            foreach (var p in e.EnumerateObject())
                if (p.Value.ValueKind == JsonValueKind.Array || p.Value.ValueKind == JsonValueKind.Object)
                    Walk(p.Value, g, rows);
        }

        private static void AddCounter(JsonElement c, CounterRow row)
        {
            if (c.ValueKind != JsonValueKind.Object) return;
            var type = c.TryGetProperty("Type", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : "";
            var name = c.TryGetProperty("Name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : "";
            bool drops = type.IndexOf("drop", StringComparison.OrdinalIgnoreCase) >= 0;

            foreach (var dirName in new[] { "Inbound", "Outbound" })
            {
                if (!c.TryGetProperty(dirName, out var d) || d.ValueKind != JsonValueKind.Object) continue;
                bool rx = dirName == "Inbound";
                if (d.TryGetProperty("DirectionTag", out var tag) && tag.ValueKind == JsonValueKind.String)
                    rx = !string.Equals(tag.GetString(), "Tx", StringComparison.OrdinalIgnoreCase);
                long packets = TryLong(d, "Packets"), bytes = TryLong(d, "Bytes");
                string reason = null, location = null;
                foreach (var p in d.EnumerateObject())
                {
                    if (p.Value.ValueKind != JsonValueKind.String) continue;
                    if (p.Name.IndexOf("Reason", StringComparison.OrdinalIgnoreCase) >= 0) reason = p.Value.GetString();
                    if (p.Name.IndexOf("Location", StringComparison.OrdinalIgnoreCase) >= 0) location = p.Value.GetString();
                }

                if (drops)
                {
                    if (rx)
                    {
                        row.RxDropPackets += packets; row.RxDropBytes += bytes;
                        if (packets > 0 && reason != null && reason != NoReason) row.RxDropReason = reason;
                        if (packets > 0 && location != null) row.RxDropLocation = location;
                    }
                    else
                    {
                        row.TxDropPackets += packets; row.TxDropBytes += bytes;
                        if (packets > 0 && reason != null && reason != NoReason) row.TxDropReason = reason;
                        if (packets > 0 && location != null) row.TxDropLocation = location;
                    }
                    if (packets > 0 && !string.IsNullOrEmpty(name)) row.DropSources.Add(name);
                }
                else
                {
                    if (rx) { if (packets > row.RxPackets) { row.RxPackets = packets; row.RxBytes = bytes; } }
                    else { if (packets > row.TxPackets) { row.TxPackets = packets; row.TxBytes = bytes; } }
                }
            }
        }

        private static bool TryInt(JsonElement e, string name, out int value)
        {
            value = 0;
            return e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out value);
        }

        private static long TryLong(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var l) ? l : 0;

        // ---- Text fallback (builds without --json) ------------------------------
        //
        // NIC: Intel(R) Ethernet Connection (4) I219-V
        //  Id Name                       Counter  Direction     Packets          Bytes | Direction     Packets          Bytes
        //  -- ----                       -------  ---------     -------          ----- | ---------     -------          -----
        //  15 Intel(R) Ethernet Conne... Drops    Rx                296        250,485 | Tx                  0              0
        //                                Upper    Rx                296        250,485 | Tx                181         33,109
        //                                (Unsupported EtherType)                       |

        private static readonly Regex TextRowRx = new Regex(
            @"^\s*(?<id>\d+)?\s+(?<name>.*?)\s*(?<counter>\S+)\s+Rx\s+(?<rxp>[\d,.]+)\s+(?<rxb>[\d,.]+)\s*\|\s*Tx\s+(?<txp>[\d,.]+)\s+(?<txb>[\d,.]+)",
            RegexOptions.Compiled);
        private static readonly Regex ReasonRx = new Regex(@"^\s+\((?<rx>[^)]*)\)\s*\|\s*(?:\((?<tx>[^)]*)\))?", RegexOptions.Compiled);
        private static readonly Regex NicRx = new Regex(@"^(?<kind>[A-Za-z][\w -]*):\s*(?<name>.+?)\s*$", RegexOptions.Compiled);

        public static List<CounterRow> ParseText(string text)
        {
            var rows = new List<CounterRow>();
            CounterRow row = null;
            string group = null;
            bool lastWasDrop = false;
            foreach (var raw in (text ?? "").Replace("\r", "").Split('\n'))
            {
                var nic = NicRx.Match(raw);
                if (nic.Success && !raw.StartsWith(" ", StringComparison.Ordinal)) { group = nic.Groups["name"].Value; continue; }

                var reason = ReasonRx.Match(raw);
                if (reason.Success && row != null && lastWasDrop)
                {
                    var r = reason.Groups["rx"].Value.Trim();
                    var t = reason.Groups["tx"].Value.Trim();
                    if (r.Length > 0 && r != NoReason) row.RxDropReason = r;
                    if (t.Length > 0 && t != NoReason) row.TxDropReason = t;
                    continue;
                }

                var m = TextRowRx.Match(raw);
                if (!m.Success) continue;
                if (m.Groups["id"].Success && m.Groups["id"].Value.Length > 0)
                {
                    row = new CounterRow
                    {
                        ComponentId = int.Parse(m.Groups["id"].Value, CultureInfo.InvariantCulture),
                        ComponentName = m.Groups["name"].Value.Trim(),
                        Group = group,
                    };
                    rows.Add(row);
                }
                if (row == null) continue;

                long P(string g) => long.Parse(Regex.Replace(m.Groups[g].Value, @"[,.]", ""), CultureInfo.InvariantCulture);
                lastWasDrop = m.Groups["counter"].Value.StartsWith("Drop", StringComparison.OrdinalIgnoreCase);
                if (lastWasDrop)
                {
                    row.RxDropPackets += P("rxp"); row.RxDropBytes += P("rxb");
                    row.TxDropPackets += P("txp"); row.TxDropBytes += P("txb");
                }
                else
                {
                    row.RxPackets = Math.Max(row.RxPackets, P("rxp")); if (row.RxPackets == P("rxp")) row.RxBytes = P("rxb");
                    row.TxPackets = Math.Max(row.TxPackets, P("txp")); if (row.TxPackets == P("txp")) row.TxBytes = P("txb");
                }
            }
            return rows;
        }
    }
}
