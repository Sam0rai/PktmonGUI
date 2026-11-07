using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using PktmonGUI.Model;

namespace PktmonGUI.Parsing
{
    /// <summary>
    /// Parses <c>pktmon status</c>. Idle prints "Packet Monitor is not running."; a running
    /// session prints headed sections whose values are indented:
    /// <code>
    /// Collected Data:
    ///     Packet counters, packet capture
    /// Monitored Components:
    ///     Network adapters
    /// Logger Parameters:
    ///     Logging mode:       Real-Time
    ///     Log file:           C:\...\PktMon.etl
    /// </code>
    /// <c>pktmon start</c> prints the same sections, so this also reads its output.
    /// </summary>
    public static class StatusParser
    {
        public static PktmonStatus Parse(string text)
        {
            text = (text ?? "").Replace("\r", "");
            var s = new PktmonStatus { Raw = text.Trim() };
            var sections = Sections(text);
            s.Running = text.IndexOf("not running", StringComparison.OrdinalIgnoreCase) < 0 &&
                        (sections.ContainsKey("Logger Parameters") || sections.ContainsKey("Collected Data"));

            if (sections.TryGetValue("Logger Parameters", out var logger))
            {
                s.LogMode = Value(logger, "Logging mode");
                s.LogFile = Value(logger, "Log file");
            }
            if (sections.TryGetValue("Monitored Components", out var comps))
                s.Components = comps.Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
            if (sections.TryGetValue("Collected Data", out var data))
                s.CollectedData = string.Join(" ", data.Select(l => l.Trim())).Trim();
            if (sections.TryGetValue("Capture Type", out var type))
                s.CaptureType = string.Join(" ", type.Select(l => l.Trim())).Trim();
            return s;
        }

        /// <summary>Unindented "Heading:" lines, each followed by its indented lines.</summary>
        public static Dictionary<string, List<string>> Sections(string text)
        {
            var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            List<string> current = null;
            foreach (var line in (text ?? "").Replace("\r", "").Split('\n'))
            {
                if (line.Length == 0) continue;
                if (!char.IsWhiteSpace(line[0]) && line.TrimEnd().EndsWith(":", StringComparison.Ordinal))
                {
                    current = new List<string>();
                    result[line.Trim().TrimEnd(':').Trim()] = current;
                }
                else if (current != null && char.IsWhiteSpace(line[0]))
                    current.Add(line);
            }
            return result;
        }

        private static string Value(List<string> lines, string key)
        {
            foreach (var l in lines)
            {
                var m = Regex.Match(l, @"^\s*" + Regex.Escape(key) + @"\s*:\s*(?<v>.*?)\s*$", RegexOptions.IgnoreCase);
                if (m.Success) return m.Groups["v"].Value;
            }
            return null;
        }
    }
}
