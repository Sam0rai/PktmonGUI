using System;
using System.Collections.Generic;
using System.Linq;
using PktmonGUI.Util;

namespace PktmonGUI.Model
{
    /// <summary>
    /// Reads filter rules from any JSON the GUI writes: an exported rule set (a <see cref="Preset"/>),
    /// presets.json (a list of presets; all their rules), a filter snapshot, or a bare list of rules.
    /// </summary>
    public static class RuleFile
    {
        /// <exception cref="FormatException">The JSON holds no rules PktmonGUI recognizes.</exception>
        public static List<FilterRule> ReadRules(string json)
        {
            // A list of presets first: a bare rule list would also "read" it, as empty rules.
            var presets = Try(() => Json.Deserialize<List<Preset>>(json));
            if (presets != null && presets.Count > 0 && presets.All(p => p?.Rules != null && p.Rules.Count > 0))
                return presets.SelectMany(p => p.Rules).ToList();

            var rules = Try(() => Json.Deserialize<List<FilterRule>>(json));
            if (rules != null && rules.Count > 0 && rules.All(r => r != null && !r.IsEmpty)) return rules;

            rules = Try(() => Json.Deserialize<Preset>(json))?.Rules;
            if (rules != null && rules.Count > 0) return rules;

            rules = Try(() => Json.Deserialize<FilterSnapshot>(json))?.Rules;
            if (rules != null && rules.Count > 0) return rules;

            throw new FormatException("The file has no rules PktmonGUI recognizes (an exported rule set, presets.json, a snapshot, or a list of rules).");
        }

        private static T Try<T>(Func<T> f) where T : class
        {
            try { return f(); } catch { return null; }
        }
    }
}
