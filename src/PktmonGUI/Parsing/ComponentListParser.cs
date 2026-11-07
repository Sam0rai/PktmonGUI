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
    /// Parses <c>pktmon list --json</c>. The JSON has changed shape between Windows builds, so
    /// this walks it structurally: any object with a numeric Id and a Name is a component, the
    /// nearest enclosing "Group"/"Name" is its group, and nested components get a parent.
    /// </summary>
    public static class ComponentListParser
    {
        public static List<Component> Parse(string output)
        {
            var text = (output ?? "").Trim();
            int start = text.IndexOfAny(new[] { '[', '{' });
            if (start >= 0)
            {
                try
                {
                    using (var doc = JsonDocument.Parse(text.Substring(start), new JsonDocumentOptions { AllowTrailingCommas = true }))
                    {
                        var list = new List<Component>();
                        Walk(doc.RootElement, null, null, false, list);
                        if (list.Count > 0) return Dedupe(list);
                    }
                }
                catch (JsonException) { }
            }
            return ParseText(text);
        }

        private static List<Component> Dedupe(List<Component> list) =>
            list.GroupBy(c => c.Id).Select(g => g.First()).ToList();

        private static void Walk(JsonElement e, string group, int? parent, bool hidden, List<Component> list)
        {
            if (e.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in e.EnumerateArray()) Walk(item, group, parent, hidden, list);
                return;
            }
            if (e.ValueKind != JsonValueKind.Object) return;

            var id = GetInt(e, "Id", "ID", "ComponentId");
            var name = GetString(e, "Name", "ComponentName", "Description");
            bool isComponent = id.HasValue && name != null;

            // A group is an object that has a name and an array of children but no numeric id.
            if (!isComponent)
            {
                var g = GetString(e, "Group", "GroupName", "Name", "Type") ?? group;
                bool groupHidden = hidden || (GetBool(e, "Hidden") ?? false);
                foreach (var p in e.EnumerateObject())
                    if (p.Value.ValueKind == JsonValueKind.Array || p.Value.ValueKind == JsonValueKind.Object)
                        Walk(p.Value, g, parent, groupHidden, list);
                return;
            }

            var c = new Component
            {
                Id = id.Value,
                Name = name,
                Group = GetString(e, "Group") ?? group,
                Type = GetString(e, "Type", "ComponentType"),
                ParentId = parent,
                Hidden = GetBool(e, "Hidden", "IsHidden") ?? hidden,
            };
            foreach (var p in e.EnumerateObject())
            {
                switch (p.Value.ValueKind)
                {
                    case JsonValueKind.String:
                    case JsonValueKind.Number:
                    case JsonValueKind.True:
                    case JsonValueKind.False:
                        c.Properties[p.Name] = Scalar(p.Value);
                        break;
                    case JsonValueKind.Array:
                        // Properties as [{ "Name": "...", "Value": "..." }] or nested components.
                        foreach (var item in p.Value.EnumerateArray())
                        {
                            if (item.ValueKind != JsonValueKind.Object) continue;
                            var pn = GetString(item, "Name", "Key", "Property");
                            var pv = item.TryGetProperty("Value", out var v) ? Scalar(v) : null;
                            if (pn != null && pv != null && !GetInt(item, "Id", "ID").HasValue)
                                c.Properties[pn] = pv;
                            else
                                Walk(item, c.Group, c.Id, c.Hidden, list);
                        }
                        break;
                    case JsonValueKind.Object:
                        if (GetInt(p.Value, "Id", "ID").HasValue) Walk(p.Value, c.Group, c.Id, c.Hidden, list);
                        else foreach (var q in p.Value.EnumerateObject())
                                if (q.Value.ValueKind != JsonValueKind.Object && q.Value.ValueKind != JsonValueKind.Array)
                                    c.Properties[q.Name] = Scalar(q.Value);
                        break;
                }
            }
            c.MacAddress = NormalizeMac(c.Properties.FirstOrDefault(kv => kv.Key.IndexOf("mac", StringComparison.OrdinalIgnoreCase) >= 0).Value);
            list.Add(c);
        }

        private static string Scalar(JsonElement v)
        {
            switch (v.ValueKind)
            {
                case JsonValueKind.String: return v.GetString();
                case JsonValueKind.Number: return v.GetRawText();
                case JsonValueKind.True: return "true";
                case JsonValueKind.False: return "false";
                default: return null;
            }
        }

        private static string GetString(JsonElement e, params string[] names)
        {
            foreach (var p in e.EnumerateObject())
                foreach (var n in names)
                    if (string.Equals(p.Name, n, StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.String)
                        return p.Value.GetString();
            return null;
        }

        private static int? GetInt(JsonElement e, params string[] names)
        {
            foreach (var p in e.EnumerateObject())
                foreach (var n in names)
                    if (string.Equals(p.Name, n, StringComparison.OrdinalIgnoreCase))
                    {
                        if (p.Value.ValueKind == JsonValueKind.Number && p.Value.TryGetInt32(out var i)) return i;
                        if (p.Value.ValueKind == JsonValueKind.String && int.TryParse(p.Value.GetString(), out i)) return i;
                    }
            return null;
        }

        private static bool? GetBool(JsonElement e, params string[] names)
        {
            foreach (var p in e.EnumerateObject())
                foreach (var n in names)
                    if (string.Equals(p.Name, n, StringComparison.OrdinalIgnoreCase))
                    {
                        if (p.Value.ValueKind == JsonValueKind.True) return true;
                        if (p.Value.ValueKind == JsonValueKind.False) return false;
                        if (p.Value.ValueKind == JsonValueKind.String && bool.TryParse(p.Value.GetString(), out var b)) return b;
                    }
            return null;
        }

        internal static string NormalizeMac(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            var hex = new string(s.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
            if (hex.Length != 12 || hex == "000000000000") return null;
            return string.Join("-", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
        }

        // ---- Text fallback --------------------------------------------------------
        //
        // Network Adapters:
        //   Id  MAC Address        Name
        //   --  -----------        ----
        //   18  00-15-5D-01-2A-3F  Intel(R) I350 Gigabit #2

        private static readonly Regex RowRx = new Regex(
            @"^\s*(?<id>\d+)\s+(?:(?<mac>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s+)?(?<name>.+?)\s*$", RegexOptions.Compiled);

        public static List<Component> ParseText(string text)
        {
            var list = new List<Component>();
            string group = null;
            foreach (var raw in (text ?? "").Split('\n'))
            {
                var line = raw.TrimEnd('\r');
                if (line.Trim().Length == 0) continue;
                if (!char.IsWhiteSpace(line[0]) && line.TrimEnd().EndsWith(":", StringComparison.Ordinal))
                {
                    group = line.Trim().TrimEnd(':');
                    continue;
                }
                if (line.TrimStart().StartsWith("--", StringComparison.Ordinal) || line.IndexOf(" Name", StringComparison.Ordinal) >= 0 && line.TrimStart().StartsWith("Id", StringComparison.OrdinalIgnoreCase))
                    continue;
                var m = RowRx.Match(line);
                if (!m.Success) continue;
                list.Add(new Component
                {
                    Id = int.Parse(m.Groups["id"].Value, CultureInfo.InvariantCulture),
                    MacAddress = m.Groups["mac"].Success ? NormalizeMac(m.Groups["mac"].Value) : null,
                    Name = m.Groups["name"].Value,
                    Group = group,
                    Type = group != null && group.IndexOf("adapter", StringComparison.OrdinalIgnoreCase) >= 0 ? "Miniport" : null,
                });
            }
            return list;
        }
    }
}
