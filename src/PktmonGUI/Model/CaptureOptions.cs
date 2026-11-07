using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace PktmonGUI.Model
{
    public enum CaptureMode
    {
        /// <summary><c>-m real-time</c>: packets stream into the grid as text. pktmon still writes its
        /// own PktMon.etl into the working folder, and PktmonGUI can save a pcapng beside it.</summary>
        Live,
        /// <summary>Writes an .etl; live counters while running, packets loaded via etl2txt after stop.</summary>
        Record,
        /// <summary><c>-o</c>: counters only, no packet data.</summary>
        CountersOnly,
    }

    public enum LogMode { Circular, MultiFile, Memory }

    public enum PacketType { All, Flow, Drop }

    public sealed class EtwProvider
    {
        public string Name { get; set; }
        public string Keywords { get; set; }
        public int? Level { get; set; }
    }

    /// <summary>Everything that ends up on the <c>pktmon start</c> line.</summary>
    public sealed class CaptureOptions
    {
        public CaptureMode Mode { get; set; } = CaptureMode.Live;

        /// <summary>Component IDs. Empty with <see cref="AllNics"/> false means pktmon's default (ALL, which duplicates packets).</summary>
        public List<int> ComponentIds { get; set; } = new List<int>();
        public bool AllNics { get; set; }

        public PacketType Type { get; set; } = PacketType.All;

        /// <summary>0 = whole packet. pktmon's default is 128.</summary>
        public int? PacketSize { get; set; } = 0;

        /// <summary>Hex event mask for <c>--flags</c>, e.g. 0x012. Null = pktmon default (0x032).</summary>
        public string Flags { get; set; }

        public string FileName { get; set; }
        public int? FileSizeMb { get; set; }
        public LogMode LogMode { get; set; } = LogMode.Circular;

        public List<EtwProvider> Providers { get; set; } = new List<EtwProvider>();

        public IEnumerable<string> ToArgs()
        {
            var a = new List<string> { "--capture" };
            if (Mode == CaptureMode.CountersOnly)
                a.Add("--counters-only");

            if (AllNics) { a.Add("--comp"); a.Add("nics"); }
            else if (ComponentIds.Count > 0)
            {
                a.Add("--comp");
                a.AddRange(ComponentIds.Select(i => i.ToString(CultureInfo.InvariantCulture)));
            }

            if (Type != PacketType.All) { a.Add("--type"); a.Add(Type.ToString().ToLowerInvariant()); }

            if (Mode != CaptureMode.CountersOnly)
            {
                if (PacketSize.HasValue) { a.Add("--pkt-size"); a.Add(PacketSize.Value.ToString(CultureInfo.InvariantCulture)); }
                if (!string.IsNullOrWhiteSpace(Flags)) { a.Add("--flags"); a.Add(Flags.Trim()); }
            }

            foreach (var p in Providers.Where(p => !string.IsNullOrWhiteSpace(p.Name)))
            {
                if (!a.Contains("--trace")) a.Add("--trace");
                a.Add("--provider"); a.Add(p.Name.Trim());
                if (!string.IsNullOrWhiteSpace(p.Keywords)) { a.Add("--keywords"); a.Add(p.Keywords.Trim()); }
                if (p.Level.HasValue) { a.Add("--level"); a.Add(p.Level.Value.ToString(CultureInfo.InvariantCulture)); }
            }

            switch (Mode)
            {
                case CaptureMode.Live:
                    a.Add("--log-mode"); a.Add("real-time");
                    break;
                case CaptureMode.Record:
                    if (!string.IsNullOrWhiteSpace(FileName)) { a.Add("--file-name"); a.Add(FileName); }
                    if (FileSizeMb.HasValue) { a.Add("--file-size"); a.Add(FileSizeMb.Value.ToString(CultureInfo.InvariantCulture)); }
                    a.Add("--log-mode"); a.Add(LogModeArg(LogMode));
                    break;
            }
            return a;
        }

        public static string LogModeArg(LogMode m) =>
            m == LogMode.MultiFile ? "multi-file" : m.ToString().ToLowerInvariant();

        public IEnumerable<string> Validate()
        {
            if (!AllNics && ComponentIds.Count == 0)
                yield return "Pick a component. Without --comp, pktmon captures on every component and each packet appears several times.";
            if (PacketSize.HasValue && PacketSize < 0) yield return "Packet size can't be negative.";
            if (Mode == CaptureMode.Record && string.IsNullOrWhiteSpace(FileName)) yield return "Record mode needs a file name.";
            if (FileSizeMb.HasValue && FileSizeMb < 1) yield return "File size must be at least 1 MB.";
            if (!string.IsNullOrWhiteSpace(Flags) && !FilterRule.TryParseNumber(Flags, out _))
                yield return "--flags must be a hex mask such as 0x012.";
            foreach (var p in Providers.Where(p => !string.IsNullOrWhiteSpace(p.Keywords)))
                if (!FilterRule.TryParseNumber(p.Keywords, out _))
                    yield return $"Keywords for {p.Name} must be a hex mask.";
        }

        public CaptureOptions Clone()
        {
            var c = (CaptureOptions)MemberwiseClone();
            c.ComponentIds = new List<int>(ComponentIds);
            c.Providers = Providers.Select(p => new EtwProvider { Name = p.Name, Keywords = p.Keywords, Level = p.Level }).ToList();
            return c;
        }
    }
}
