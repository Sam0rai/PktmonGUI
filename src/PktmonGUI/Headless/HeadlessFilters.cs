using System;
using System.Collections.Generic;
using System.Linq;
using PktmonGUI.Model;

namespace PktmonGUI.Headless
{
    /// <summary>The rules a headless capture applies: --filter, --preset and --filters-file together.</summary>
    public static class HeadlessFilters
    {
        /// <summary>
        /// Every rule is named "PktmonGUI …", so if a run dies with them on the machine, anyone (and
        /// <see cref="Services.OwnerGuess"/>) can tell whose they are.
        /// </summary>
        public const string NamePrefix = "PktmonGUI ";

        public static List<FilterRule> Build(HeadlessOptions o, Func<string, string> readFile, out string error)
        {
            error = null;
            var rules = new List<FilterRule>();

            foreach (var text in o.Filters)
            {
                if (!FilterRule.TryParse(text, out var rule, out var e)) { error = $"--filter \"{text}\": {e}"; return null; }
                rules.Add(rule);
            }
            foreach (var name in o.Presets)
            {
                var preset = BuiltIn.Find(name);
                if (preset == null) { error = $"--preset '{name}' isn't a built-in preset ({string.Join(", ", BuiltIn.Slugs)})."; return null; }
                rules.AddRange(preset.Rules.Select(r => r.Clone()));
            }
            if (o.FiltersFile != null)
            {
                try { rules.AddRange(RuleFile.ReadRules(readFile(o.FiltersFile)).Select(r => r.Clone())); }
                catch (Exception ex) { error = $"--filters-file {o.FiltersFile}: {ex.Message}"; return null; }
            }

            if (rules.Count > FilterRule.MaxRules)
            {
                error = $"{rules.Count} rules given; pktmon allows at most {FilterRule.MaxRules}.";
                return null;
            }
            for (int i = 0; i < rules.Count; i++)
            {
                var r = rules[i];
                var baseName = string.IsNullOrWhiteSpace(r.Name) ? (i + 1).ToString() : r.Name.Trim();
                r.Name = baseName.StartsWith(NamePrefix.Trim(), StringComparison.OrdinalIgnoreCase) ? baseName : NamePrefix + baseName;
                var e = r.Validate().FirstOrDefault();
                if (e != null) { error = $"Rule \"{r.Name}\": {e}"; return null; }
            }
            return rules;
        }
    }
}
