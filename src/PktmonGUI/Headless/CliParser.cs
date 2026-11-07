using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using PktmonGUI.Model;

namespace PktmonGUI.Headless
{
    /// <summary>
    /// Parses headless-mode arguments. Driven by one flag table, which the usage text is tested
    /// against. Flags are case-insensitive and take their value as the next argument or after '='.
    /// </summary>
    public static class CliParser
    {
        private sealed class Flag
        {
            public string Name;
            public bool TakesValue;
            /// <summary>The value may itself start with '-' or '--' (a pktmon filter).</summary>
            public bool Verbatim;
            public bool Hidden;
            public CliAction? Action;
            public CliAction[] AllowedFor = new CliAction[0];
            public bool ImpliesCapture;
            public Func<HeadlessOptions, string, string> Apply = (o, v) => null;
        }

        private static readonly CliAction[] Everything = { CliAction.Capture, CliAction.Stop, CliAction.Status, CliAction.Cleanup, CliAction.ListAdapters };

        private static Flag ActionFlag(string name, CliAction action) => new Flag { Name = name, Action = action };

        private static Flag CaptureFlag(string name, Func<HeadlessOptions, string, string> apply, bool takesValue = true, bool hidden = false) =>
            new Flag { Name = name, TakesValue = takesValue, Apply = apply, AllowedFor = new[] { CliAction.Capture }, ImpliesCapture = true, Hidden = hidden };

        private static Flag Switch(string name, Action<HeadlessOptions> set, params CliAction[] allowed) =>
            new Flag { Name = name, Apply = (o, v) => { set(o); return null; }, AllowedFor = allowed };

        private static readonly List<Flag> Flags = new List<Flag>
        {
            ActionFlag("--capture", CliAction.Capture),
            ActionFlag("--stop", CliAction.Stop),
            ActionFlag("--status", CliAction.Status),
            ActionFlag("--cleanup", CliAction.Cleanup),
            ActionFlag("--list-adapters", CliAction.ListAdapters),
            ActionFlag("--help", CliAction.Help),
            ActionFlag("--version", CliAction.Version),

            CaptureFlag("--duration", (o, v) =>
            {
                if (!DurationParser.TryParse(v, out var d, out var e)) return e;
                o.Duration = d;
                return null;
            }),
            CaptureFlag("--comp", (o, v) =>
            {
                var parts = SplitList(v);
                if (parts.Count == 0) return "give nics, default, or adapters (see --list-adapters)";
                o.Components.AddRange(parts);
                return null;
            }),
            new Flag
            {
                Name = "--filter", TakesValue = true, Verbatim = true, AllowedFor = new[] { CliAction.Capture }, ImpliesCapture = true,
                Apply = (o, v) =>
                {
                    if (string.IsNullOrWhiteSpace(v)) return "is empty";
                    if (!FilterRule.TryParse(v, out _, out var e)) return $"\"{v}\": {e}";
                    o.Filters.Add(v);
                    return null;
                },
            },
            CaptureFlag("--preset", (o, v) =>
            {
                var parts = SplitList(v);
                if (parts.Count == 0) return "is empty";
                foreach (var p in parts)
                    if (BuiltIn.Find(p) == null) return $"'{p}' isn't a built-in preset ({string.Join(", ", BuiltIn.Slugs)})";
                o.Presets.AddRange(parts);
                return null;
            }),
            CaptureFlag("--filters-file", (o, v) => { o.FiltersFile = v; return null; }),
            CaptureFlag("--keep-filters", (o, v) => { o.KeepFilters = true; return null; }, takesValue: false),
            CaptureFlag("--pkt-size", (o, v) =>
            {
                if (!int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var n)) return $"'{v}' isn't a number of bytes (0 = whole packet)";
                o.PacketSize = n;
                return null;
            }),
            CaptureFlag("--type", (o, v) =>
            {
                switch ((v ?? "").ToLowerInvariant())
                {
                    case "all": o.Type = PacketType.All; return null;
                    case "flow": o.Type = PacketType.Flow; return null;
                    case "drop": o.Type = PacketType.Drop; return null;
                    default: return $"'{v}' isn't all, flow or drop";
                }
            }),
            CaptureFlag("--file-size", (o, v) =>
            {
                if (!TryParseSizeMb(v, out var mb)) return $"'{v}' isn't a size: use MB (512) or add MB/GB (2GB)";
                o.FileSizeMb = mb;
                return null;
            }),
            CaptureFlag("--log-mode", (o, v) =>
            {
                switch ((v ?? "").ToLowerInvariant())
                {
                    case "circular": o.LogMode = LogMode.Circular; return null;
                    case "multi-file": case "multifile": o.LogMode = LogMode.MultiFile; return null;
                    default: return $"'{v}' isn't circular or multi-file";
                }
            }),
            CaptureFlag("--no-attribution", (o, v) => { o.NoAttribution = true; return null; }, takesValue: false),
            CaptureFlag("--no-pcap", (o, v) => { o.NoPcap = true; return null; }, takesValue: false),
            CaptureFlag("--no-settings", (o, v) => { o.NoSettings = true; return null; }, takesValue: false),
            // A detached child: its defaults came from this settings.json ("<path>|<flag>,<flag>"), already in its arguments.
            CaptureFlag("--settings-from", (o, v) =>
            {
                int bar = v.LastIndexOf('|');
                if (bar <= 0) return "isn't <file>|<flags>";
                o.NoSettings = true;
                o.SettingsFile = v.Substring(0, bar);
                o.SettingsApplied = SplitList(v.Substring(bar + 1));
                return null;
            }, hidden: true),
            CaptureFlag("--out", (o, v) => { o.Out = v; return null; }),
            CaptureFlag("--collect", (o, v) => { o.Collect = v; return null; }),
            CaptureFlag("--keep-local", (o, v) => { o.KeepLocal = true; return null; }, takesValue: false),
            CaptureFlag("--detach", (o, v) => { o.Detach = true; return null; }, takesValue: false),
            CaptureFlag("--detached-child", (o, v) => { o.DetachedChild = true; return null; }, takesValue: false, hidden: true),
            CaptureFlag("--run-folder", (o, v) => { o.RunFolder = v; return null; }, hidden: true),

            new Flag { Name = "--force", Apply = (o, v) => { o.Force = true; return null; }, AllowedFor = new[] { CliAction.Capture, CliAction.Cleanup }, ImpliesCapture = true },
            Switch("--purge", o => o.Purge = true, CliAction.Cleanup),
            new Flag
            {
                Name = "--timeout", TakesValue = true, AllowedFor = new[] { CliAction.Stop, CliAction.Capture },
                Apply = (o, v) =>
                {
                    if (!DurationParser.TryParse(v, out var t, out var e)) return e;
                    if (t <= TimeSpan.Zero) return "must be more than 0";
                    o.Timeout = t;
                    return null;
                },
            },
            Switch("--json", o => o.Json = true, Everything),
            Switch("--quiet", o => o.Quiet = true, Everything),
            new Flag { Name = "--log", TakesValue = true, Apply = (o, v) => { o.LogFile = v; return null; }, AllowedFor = Everything },
        };

        private static readonly Dictionary<string, Flag> ByName = Flags.ToDictionary(f => f.Name, StringComparer.OrdinalIgnoreCase);

        /// <summary>Every flag a user may type; the usage text must mention each.</summary>
        public static IEnumerable<string> PublicFlagNames => Flags.Where(f => !f.Hidden).Select(f => f.Name);

        /// <summary>True for flags followed by a value (used to walk arguments when re-launching a detached child).</summary>
        public static bool TakesValue(string name) => ByName.TryGetValue(name, out var f) && f.TakesValue;

        /// <summary>The flags given in <paramref name="args"/> (a value is never mistaken for a flag).</summary>
        public static HashSet<string> GivenFlags(IReadOnlyList<string> args)
        {
            var given = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Count; i++)
            {
                var token = args[i];
                int eq = token.IndexOf('=');
                var name = eq > 0 ? token.Substring(0, eq) : token;
                if (!ByName.TryGetValue(name, out var f)) continue;
                given.Add(f.Name);
                if (f.TakesValue && eq < 0) i++;
            }
            return given;
        }

        public static CliParseResult Parse(IReadOnlyList<string> args)
        {
            var o = new HeadlessOptions { RawArgs = args.ToList() };
            var actions = new List<string>();
            var used = new List<Flag>();
            bool help = false;

            for (int i = 0; i < args.Count; i++)
            {
                var token = args[i];
                if (token == "-h" || token == "-?" || token == "/?") { help = true; continue; }
                if (!token.StartsWith("--", StringComparison.Ordinal))
                    return Fail($"Unexpected '{token}'. Options start with -- (run PktmonGUI.exe --help).");

                string name = token, value = null;
                int eq = token.IndexOf('=');
                if (eq > 0) { name = token.Substring(0, eq); value = token.Substring(eq + 1); }
                if (!ByName.TryGetValue(name, out var flag))
                    return Fail($"Unknown option '{name}'. Run PktmonGUI.exe --help for the options.");

                if (flag.Action.HasValue)
                {
                    if (value != null) return Fail($"{flag.Name} takes no value.");
                    if (flag.Action == CliAction.Help) help = true;
                    else if (!actions.Contains(flag.Name)) actions.Add(flag.Name);
                    continue;
                }

                if (flag.TakesValue)
                {
                    if (value == null)
                    {
                        if (i + 1 >= args.Count || (!flag.Verbatim && args[i + 1].StartsWith("--", StringComparison.Ordinal)))
                            return Fail($"{flag.Name} needs a value.");
                        value = args[++i];
                    }
                }
                else if (value != null) return Fail($"{flag.Name} takes no value.");

                used.Add(flag);
                var err = flag.Apply(o, value);
                if (err != null) return Fail($"{flag.Name}: {err}.");
            }

            if (help) { o.Action = CliAction.Help; return new CliParseResult { Options = o }; }
            if (actions.Count > 1) return Fail($"{actions[0]} and {actions[1]} can't be combined: give one action.");
            if (actions.Count == 1) o.Action = ByName[actions[0]].Action.Value;
            else if (used.Any(f => f.ImpliesCapture)) o.Action = CliAction.Capture;
            else return Fail("Nothing to do: give an action such as --capture, --stop or --status (run PktmonGUI.exe --help).");

            if (o.Action == CliAction.Version) return new CliParseResult { Options = o };
            foreach (var f in used)
                if (!f.AllowedFor.Contains(o.Action))
                    return Fail($"{f.Name} doesn't apply to {ActionName(o.Action)}.");

            var cross = CrossCheck(o);
            return cross == null ? new CliParseResult { Options = o } : Fail(cross);
        }

        private static string CrossCheck(HeadlessOptions o)
        {
            if (o.LogFile != null && !IsRooted(o.LogFile)) return "--log must be a full path.";
            if (o.Action != CliAction.Capture) return null;
            if (o.KeepFilters && (o.Filters.Count > 0 || o.Presets.Count > 0 || o.FiltersFile != null))
                return "--keep-filters captures through the machine's own filters; it can't be combined with --filter, --preset or --filters-file.";
            if (o.Components.Any(c => c.Equals("nics", StringComparison.OrdinalIgnoreCase)) && o.Components.Count > 1)
                return "--comp nics already means every network adapter; don't list others with it.";
            if (o.Timeout.HasValue && !o.Detach)
                return "--timeout applies to --stop and --detach.";
            if (o.Detach && o.DetachedChild) return "--detach and --detached-child can't be combined.";
            if (o.DetachedChild && string.IsNullOrEmpty(o.RunFolder)) return "--detached-child needs --run-folder.";
            if (o.Out != null)
            {
                var e = HeadlessPaths.ValidateOut(o.Out);
                if (e != null) return "--out: " + e;
            }
            if (o.RunFolder != null && !IsRooted(o.RunFolder)) return "--run-folder must be a full path.";
            if (o.Collect != null && !IsRooted(o.Collect)) return "--collect must be a full path, e.g. \\\\server\\share or D:\\captures.";
            if (o.FileSizeMb < 1) return "--file-size must be at least 1 MB.";
            return null;
        }

        private static bool IsRooted(string p)
        {
            try { return Path.IsPathRooted(p) && (p.StartsWith(@"\\", StringComparison.Ordinal) || (p.Length >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))); }
            catch { return false; }
        }

        private static string ActionName(CliAction a)
        {
            switch (a)
            {
                case CliAction.ListAdapters: return "--list-adapters";
                default: return "--" + a.ToString().ToLowerInvariant();
            }
        }

        private static List<string> SplitList(string v) =>
            (v ?? "").Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

        /// <summary>512, 512MB, 2GB (case-insensitive) → MB.</summary>
        internal static bool TryParseSizeMb(string v, out int mb)
        {
            mb = 0;
            var s = (v ?? "").Trim().ToUpperInvariant();
            long factor = 1;
            if (s.EndsWith("GB", StringComparison.Ordinal)) { factor = 1024; s = s.Substring(0, s.Length - 2); }
            else if (s.EndsWith("MB", StringComparison.Ordinal)) s = s.Substring(0, s.Length - 2);
            if (!long.TryParse(s.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n < 1) return false;
            var total = n * factor;
            if (total > int.MaxValue) return false;
            mb = (int)total;
            return true;
        }

        private static CliParseResult Fail(string error) => new CliParseResult { Error = error };
    }
}
