using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using PktmonGUI.Model;
using PktmonGUI.Pktmon;
using PktmonGUI.Services;

namespace PktmonGUI.Headless
{
    /// <summary>
    /// A capture's defaults from the settings.json shipped beside the exe (see <see cref="SettingsTemplate"/>),
    /// so an administrator can copy the tool with its settings to a server and run it there. They're added
    /// as the flags the command line didn't give, so flags always win, the parser checks them like typed
    /// ones, and a detached child gets them in its arguments.
    /// </summary>
    internal static class CliDefaults
    {
        /// <summary>
        /// Adds the template's defaults to <paramref name="parsed"/>'s capture. Returns the options to use,
        /// or null with <paramref name="error"/> set when the template can't be used.
        /// </summary>
        public static HeadlessOptions Apply(IReadOnlyList<string> args, HeadlessOptions parsed, SettingsTemplate template, out string error)
        {
            error = null;
            if (template == null || parsed.Action != CliAction.Capture || parsed.NoSettings || parsed.DetachedChild) return parsed;
            if (!template.Usable)
            {
                error = $"The settings.json beside PktmonGUI.exe can't be used: {template.Error ?? template.Untrusted} " +
                        "Fix it, or add --no-settings to capture without it.";
                return null;
            }

            var extra = ArgsFrom(template, CliParser.GivenFlags(args));
            var merged = CliParser.Parse(args.Concat(extra).ToList());
            if (!merged.Ok)
            {
                error = $"{template.Path}: {merged.Error}";
                return null;
            }
            var o = merged.Options;
            o.SettingsFile = template.Path;
            o.SettingsApplied = CliParser.GivenFlags(extra).OrderBy(f => f, StringComparer.Ordinal).ToList();
            return o;
        }

        /// <summary>The flags the template gives that <paramref name="given"/> doesn't already have.</summary>
        internal static List<string> ArgsFrom(SettingsTemplate t, ISet<string> given)
        {
            var v = t.Values;
            var a = new List<string>();
            if (v == null) return a;
            if (t.Sets("workingFolder") && !given.Contains("--out")) { a.Add("--out"); a.Add(v.WorkingFolder); }
            if (t.Sets("recordFileSizeMb") && !given.Contains("--file-size")) { a.Add("--file-size"); a.Add(v.RecordFileSizeMb.ToString(CultureInfo.InvariantCulture)); }
            if (t.Sets("recordLogMode") && !given.Contains("--log-mode")) { a.Add("--log-mode"); a.Add(v.RecordLogMode == LogMode.MultiFile ? "multi-file" : "circular"); }
            if ((t.Sets("fullPacket") || t.Sets("snapLength")) && !given.Contains("--pkt-size"))
            {
                a.Add("--pkt-size");
                a.Add((v.FullPacket ? 0 : v.SnapLength).ToString(CultureInfo.InvariantCulture));
            }
            if (t.Sets("attributeProcesses") && !v.AttributeProcesses && !given.Contains("--no-attribution")) a.Add("--no-attribution");
            bool filtersGiven = given.Contains("--filter") || given.Contains("--preset") || given.Contains("--filters-file") || given.Contains("--keep-filters");
            if (t.Sets("draftRules") && !filtersGiven)
                foreach (var rule in (v.DraftRules ?? new List<FilterRule>()).Where(r => r != null && !r.IsEmpty))
                {
                    a.Add("--filter");
                    a.Add(string.Join(" ", rule.ToArgs().Select(PktmonCommand.QuoteArg)));
                }
            return a;
        }

        /// <summary>The detached child's --settings-from value, or null when no settings.json gave defaults.</summary>
        public static string ChildMarker(HeadlessOptions o) =>
            o.SettingsFile == null ? null : o.SettingsFile + "|" + string.Join(",", o.SettingsApplied);
    }
}
