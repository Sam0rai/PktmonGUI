using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PktmonGUI.Model;
using PktmonGUI.Parsing;
using PktmonGUI.Pktmon;

namespace PktmonGUI.Services
{
    public sealed class MachineFilters
    {
        public string Raw { get; set; } = "";
        public List<ExistingFilter> Filters { get; set; } = new List<ExistingFilter>();
        /// <summary>True when these are exactly the rules PktmonGUI last applied.</summary>
        public bool AreOurs { get; set; }
        public string Owner { get; set; }
        public int Count => Filters.Count;
        public bool HasForeign => Count > 0 && !AreOurs;
    }

    /// <summary>
    /// pktmon keeps one filter set per machine, shared by every admin and by services
    /// such as Defender for Endpoint, and can only clear it all at once. This service
    /// makes "apply" safe: read, snapshot foreign rules, clear, add, verify.
    /// </summary>
    public sealed class FilterService
    {
        private readonly PktmonRunner _runner;
        private readonly SnapshotService _snapshots;
        private readonly SettingsStore _settings;

        public FilterService(PktmonRunner runner, SnapshotService snapshots, SettingsStore settings)
        {
            _runner = runner;
            _snapshots = snapshots;
            _settings = settings;
        }

        public MachineFilters Current { get; private set; } = new MachineFilters();

        public event EventHandler Changed;

        public async Task<MachineFilters> ReadAsync(bool log = true)
        {
            var r = await _runner.RunAsync(PktmonCommand.FilterList(), log).ConfigureAwait(false);
            if (!r.Success) throw r.ToException();
            var filters = FilterListParser.Parse(r.StdOut);
            var mf = new MachineFilters
            {
                Raw = r.StdOut,
                Filters = filters,
                AreOurs = filters.Count > 0 && Normalize(r.StdOut) == Normalize(_settings.Settings.AppliedFilterListRaw),
                Owner = OwnerGuess.Guess(filters.Select(f => f.Rule.Name)),
            };
            Current = mf;
            Changed?.Invoke(this, EventArgs.Empty);
            return mf;
        }

        private static string Normalize(string s) =>
            s == null ? null : string.Join("\n", s.Split('\n').Select(l => l.TrimEnd()).Where(l => l.Length > 0));

        /// <summary>
        /// Replaces the machine's filters with <paramref name="rules"/>. When foreign filters exist and
        /// <paramref name="snapshotForeign"/> is set, they're saved first so they can be put back on stop.
        /// </summary>
        public async Task ApplyAsync(IReadOnlyList<FilterRule> rules, bool snapshotForeign, bool restoreOnStop)
        {
            if (rules.Count > FilterRule.MaxRules)
                throw new InvalidOperationException($"pktmon allows at most {FilterRule.MaxRules} filters.");
            foreach (var rule in rules)
            {
                var err = rule.Validate().FirstOrDefault();
                if (err != null) throw new InvalidOperationException($"Rule \"{rule.Name ?? rule.ShortLabel}\": {err}");
            }

            var before = await ReadAsync().ConfigureAwait(false);
            if (before.HasForeign && snapshotForeign && _snapshots.Active == null)
                _snapshots.Save(before.Filters, before.Raw, restoreOnStop);

            if (before.Count > 0)
                await _runner.RunCheckedAsync(PktmonCommand.FilterRemove(
                    before.Count == 1 ? "clears 1 filter, the only granularity pktmon has"
                                      : $"clears all {before.Count}, the only granularity pktmon has")).ConfigureAwait(false);

            for (int i = 0; i < rules.Count; i++)
            {
                var r = await _runner.RunAsync(PktmonCommand.FilterAdd(rules[i], i == 1 ? "rules are OR'd" : null)).ConfigureAwait(false);
                if (!r.Success) throw r.ToException();
            }

            var after = await ReadAsync().ConfigureAwait(false);
            _settings.Settings.AppliedFilterListRaw = rules.Count == 0 ? null : after.Raw;
            _settings.Settings.AppliedRules = rules.Select(r => r.Clone()).ToList();
            _settings.Save();
            after.AreOurs = rules.Count > 0;
            Current = after;
            Changed?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>Clears every filter on the machine (after snapshotting foreign ones if asked).</summary>
        public Task ClearAsync(bool snapshotForeign, bool restoreOnStop) =>
            ApplyAsync(new FilterRule[0], snapshotForeign, restoreOnStop);
    }
}
