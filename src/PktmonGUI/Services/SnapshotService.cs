using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PktmonGUI.Model;
using PktmonGUI.Pktmon;
using PktmonGUI.Util;

namespace PktmonGUI.Services
{
    /// <summary>
    /// Saves the machine's filter set before PktmonGUI clears it, and replays it afterwards.
    /// A snapshot with RestoreOnStop=true and Restored=false doubles as the crash marker:
    /// if one exists at launch, the previous session never got to put the filters back.
    /// </summary>
    public sealed class SnapshotService
    {
        private readonly PktmonRunner _runner;
        private readonly CommandLog _log;

        public SnapshotService(PktmonRunner runner, CommandLog log, string dataFolder)
        {
            _runner = runner;
            _log = log;
            Folder = Path.Combine(dataFolder, "snapshots");
        }

        public string Folder { get; }

        /// <summary>The snapshot taken in this session, if any.</summary>
        public FilterSnapshot Active { get; private set; }
        public string ActivePath { get; private set; }

        public string Save(IReadOnlyList<ExistingFilter> filters, string rawList, bool restoreOnStop)
        {
            var snap = new FilterSnapshot
            {
                Taken = DateTime.Now,
                Machine = Environment.MachineName,
                Owner = OwnerGuess.Guess(filters.Select(f => f.Rule.Name)),
                RestoreOnStop = restoreOnStop,
                RawFilterList = rawList,
                Rules = filters.Where(f => f.FullyParsed).Select(f => f.Rule).ToList(),
                UnparsedLines = filters.Where(f => !f.FullyParsed).Select(f => f.RawText).ToList(),
            };
            var path = Path.Combine(Folder, snap.Taken.ToString("yyyy-MM-dd'T'HHmmss") + ".json");
            Json.Save(path, snap);
            Active = snap;
            ActivePath = path;
            _log.Note($"{filters.Count} filters saved to {path}");
            return path;
        }

        public void SetRestoreOnStop(bool value)
        {
            if (Active == null) return;
            Active.RestoreOnStop = value;
            Json.Save(ActivePath, Active);
        }

        public bool HasPendingRestore => Active != null && Active.RestoreOnStop && !Active.Restored;

        /// <summary>
        /// Replays the snapshot: <c>filter remove</c> then one <c>filter add</c> per rule.
        /// Returns the rules that failed to re-add.
        /// </summary>
        public async Task<List<string>> RestoreAsync(FilterSnapshot snap = null, string path = null)
        {
            snap = snap ?? Active;
            path = path ?? ActivePath;
            var failures = new List<string>();
            if (snap == null) return failures;

            await _runner.RunAsync(PktmonCommand.FilterRemove("clear PktmonGUI's rules before restoring the snapshot")).ConfigureAwait(false);
            foreach (var rule in snap.Rules)
            {
                var r = await _runner.RunAsync(PktmonCommand.FilterAdd(rule, "restored from snapshot")).ConfigureAwait(false);
                if (!r.Success) failures.Add($"{rule.Name ?? rule.ArgsSummary}: {r.Output.Trim()}");
            }
            failures.AddRange(snap.UnparsedLines.Select(l => "Could not be restored automatically: " + l.Trim()));

            snap.Restored = true;
            try { if (path != null) Json.Save(path, snap); } catch { }
            _log.Note(failures.Count == 0
                ? $"Snapshot restored: {snap.Rules.Count} filters put back"
                : $"Snapshot restored with {failures.Count} problems");
            if (ReferenceEquals(snap, Active)) { Active = null; ActivePath = null; }
            return failures;
        }

        /// <summary>Snapshots from earlier sessions that were meant to be restored but never were.</summary>
        public List<KeyValuePair<string, FilterSnapshot>> FindUnrestored()
        {
            var result = new List<KeyValuePair<string, FilterSnapshot>>();
            if (!Directory.Exists(Folder)) return result;
            foreach (var file in Directory.GetFiles(Folder, "*.json").OrderByDescending(f => f))
            {
                try
                {
                    var s = Json.Load<FilterSnapshot>(file);
                    if (s != null && s.RestoreOnStop && !s.Restored &&
                        string.Equals(s.Machine, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                        result.Add(new KeyValuePair<string, FilterSnapshot>(file, s));
                }
                catch { }
            }
            return result;
        }

        public void Dismiss(string path, FilterSnapshot snap)
        {
            snap.RestoreOnStop = false;
            try { Json.Save(path, snap); } catch { }
        }

        /// <summary>After a crash, adopt the snapshot so it's restored at the end of this session instead.</summary>
        public void Adopt(string path, FilterSnapshot snap)
        {
            Active = snap;
            ActivePath = path;
        }
    }

    /// <summary>Guesses who owns a filter set from its rule names.</summary>
    public static class OwnerGuess
    {
        public static string Guess(IEnumerable<string> names)
        {
            var list = names.Where(n => !string.IsNullOrEmpty(n)).ToList();
            if (list.Count == 0) return "unknown (unnamed rules)";
            if (list.Any(n => n.StartsWith("SenseNdr", StringComparison.OrdinalIgnoreCase)))
                return "Defender for Endpoint";
            if (list.Any(n => n.IndexOf("PktmonGUI", StringComparison.OrdinalIgnoreCase) >= 0))
                return "PktmonGUI";
            var common = list.GroupBy(n => n).OrderByDescending(g => g.Count()).First();
            return common.Count() > 1 ? $"\"{common.Key}\" rules" : "another admin or tool";
        }
    }
}
