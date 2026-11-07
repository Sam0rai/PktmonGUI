using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PktmonGUI.Attribution;
using PktmonGUI.Model;
using PktmonGUI.Util;

namespace PktmonGUI.Services
{
    /// <summary>
    /// Where a recording's files are. A multi-file capture asked for as name.etl is written by pktmon as
    /// name1.etl, name2.etl…, while PktmonGUI saves its metadata and process data once, beside name.etl.
    /// </summary>
    public static class CaptureFiles
    {
        private static readonly string MultiFile = CaptureOptions.LogModeArg(LogMode.MultiFile);

        /// <summary>The name.etl a multi-file part belongs to, or null if the file isn't a part.</summary>
        public static string ParentOf(string path)
        {
            if (!path.EndsWith(".etl", StringComparison.OrdinalIgnoreCase) || File.Exists(CaptureSession.MetaPathFor(path))) return null;
            var stem = Path.GetFileNameWithoutExtension(path);
            var dir = Path.GetDirectoryName(path);
            // The name itself may end in digits (capture-20261028-151200), so try each split of the trailing digits.
            for (var n = 1; n < stem.Length && char.IsDigit(stem[stem.Length - n]); n++)
            {
                var parent = Path.Combine(dir, stem.Substring(0, stem.Length - n) + ".etl");
                if (LoadOwnMeta(parent)?.LogMode == MultiFile) return parent;
            }
            return null;
        }

        /// <summary>The parts pktmon wrote for a multi-file capture, in the order written; empty if none.</summary>
        public static IReadOnlyList<string> PartsOf(string etl)
        {
            etl = Path.GetFullPath(etl);
            var dir = Path.GetDirectoryName(etl);
            var stem = Path.GetFileNameWithoutExtension(etl);
            if (!Directory.Exists(dir)) return new string[0];
            return Directory.GetFiles(dir, stem + "*.etl")
                .Where(f => string.Equals(ParentOf(f), etl, StringComparison.OrdinalIgnoreCase))
                .Select(f => new { Path = f, Number = long.Parse(Path.GetFileNameWithoutExtension(f).Substring(stem.Length)) })
                .OrderBy(p => p.Number)
                .Select(p => p.Path)
                .ToList();
        }

        /// <summary>
        /// The newest parts, oldest first, that fit in <paramref name="maxBytes"/> together (always at least
        /// one). The last part is often only the final second of a capture, so loading just that shows little.
        /// </summary>
        public static IReadOnlyList<string> NewestParts(IReadOnlyList<string> parts, long maxBytes)
        {
            var take = new List<string>();
            long bytes = 0;
            for (var i = parts.Count - 1; i >= 0; i--)
            {
                var size = new FileInfo(parts[i]).Length;
                if (take.Count > 0 && bytes + size > maxBytes) break;
                take.Insert(0, parts[i]);
                bytes += size;
            }
            return take;
        }

        /// <summary>The capture's metadata: its own, or for a multi-file part, the whole capture's.</summary>
        public static CaptureMeta MetaFor(string path) => LoadOwnMeta(path) ?? (ParentOf(path) is string parent ? LoadOwnMeta(parent) : null);

        /// <summary>The process data recorded with the capture; a multi-file part shares its capture's.</summary>
        public static string AttributionPathFor(string path) => AttributionSnapshot.PathFor(ParentOf(path) ?? path);

        private static CaptureMeta LoadOwnMeta(string etl)
        {
            try { return Json.Load<CaptureMeta>(CaptureSession.MetaPathFor(etl)); } catch { return null; }
        }
    }
}
