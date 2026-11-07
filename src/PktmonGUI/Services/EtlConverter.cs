using System;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using PktmonGUI.Attribution;
using PktmonGUI.Pcap;
using PktmonGUI.Pktmon;
using PktmonGUI.Util;

namespace PktmonGUI.Services
{
    /// <summary>What <c>pktmon etl2pcap</c> reported at the end of its output.</summary>
    public sealed class Etl2PcapSummary
    {
        public long? PacketsTotal { get; set; }
        public long? Drops { get; set; }
        public long? Formatted { get; set; }
        public string FormattedFile { get; set; }
    }

    public sealed class EtlConversion
    {
        public string Etl { get; set; }
        public string Pcapng { get; set; }
        public Etl2PcapSummary Summary { get; set; }
        /// <summary>Null when there was no attribution sidecar, or adding the comments failed.</summary>
        public CommentResult Comments { get; set; }
        /// <summary>etl2pcap failed; the .etl is untouched.</summary>
        public string Error { get; set; }
        /// <summary>The pcapng was written, but its process comments couldn't be added.</summary>
        public string CommentError { get; set; }
        public bool Success => Error == null;
    }

    /// <summary>.etl → pcapng, then a "Process: …" comment on every packet from the capture's attribution sidecar.</summary>
    public static class EtlConverter
    {
        public static async Task<EtlConversion> ToPcapngAsync(PktmonRunner runner, string etl, string pcapng, string sidecar)
        {
            var result = new EtlConversion { Etl = etl, Pcapng = pcapng };
            var r = await runner.RunAsync(PktmonCommand.Etl2Pcap(etl, pcapng, dropOnly: false, componentId: null),
                                          timeout: TimeSpan.FromHours(2)).ConfigureAwait(false);
            if (!r.Success)
            {
                result.Error = $"etl2pcap failed (exit {r.ExitCode}): {r.Output}".Trim();
                return result;
            }
            result.Summary = ParseSummary(r.Output);
            if (sidecar != null && File.Exists(sidecar) && File.Exists(pcapng))
            {
                try { result.Comments = await Task.Run(() => AddProcessComments(pcapng, sidecar)).ConfigureAwait(false); }
                catch (Exception ex) { result.CommentError = ex.Message; }
            }
            return result;
        }

        /// <summary>Rewrites <paramref name="pcapng"/> in place with the processes recorded in <paramref name="sidecar"/>.</summary>
        public static CommentResult AddProcessComments(string pcapng, string sidecar) =>
            ProcessCommenter.Annotate(pcapng, pcapng, Json.Load<AttributionSnapshot>(sidecar), Path.GetFileName(sidecar));

        /// <summary>
        /// Reads the tail etl2pcap prints:
        /// <code>
        /// Packets total:       303
        /// Packet drop count:   199
        /// Packets formatted:   303
        /// Formatted file:      C:\...\rec.pcapng
        /// </code>
        /// </summary>
        public static Etl2PcapSummary ParseSummary(string output)
        {
            var s = new Etl2PcapSummary();
            foreach (var raw in (output ?? "").Replace("\r", "").Split('\n'))
            {
                var m = Regex.Match(raw, @"^\s*(?<k>[A-Za-z ]+?)\s*:\s*(?<v>.+?)\s*$");
                if (!m.Success) continue;
                var key = m.Groups["k"].Value;
                var value = m.Groups["v"].Value;
                if (key.Equals("Packets total", StringComparison.OrdinalIgnoreCase)) s.PacketsTotal = Number(value);
                else if (key.Equals("Packet drop count", StringComparison.OrdinalIgnoreCase)) s.Drops = Number(value);
                else if (key.Equals("Packets formatted", StringComparison.OrdinalIgnoreCase)) s.Formatted = Number(value);
                else if (key.Equals("Formatted file", StringComparison.OrdinalIgnoreCase)) s.FormattedFile = value;
            }
            return s;
        }

        private static long? Number(string s) =>
            long.TryParse(s.Replace(",", "").Replace(".", ""), NumberStyles.None, CultureInfo.InvariantCulture, out var v) ? v : (long?)null;
    }
}
