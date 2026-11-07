using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PktmonGUI.Pktmon
{
    /// <summary>
    /// One pktmon invocation: the argument vector plus a human note shown in the
    /// "Commands run" panels. Building commands here keeps the GUI honest: what the
    /// panel shows is exactly what was executed.
    /// </summary>
    public sealed class PktmonCommand
    {
        public PktmonCommand(IEnumerable<string> args, string note = null, string executable = "pktmon")
        {
            Args = args.Where(a => a != null).ToList();
            Note = note;
            Executable = executable;
        }

        public string Executable { get; }
        public IReadOnlyList<string> Args { get; }
        public string Note { get; }

        /// <summary>Argument string passed to CreateProcess.</summary>
        public string ArgumentString => string.Join(" ", Args.Select(QuoteArg));

        /// <summary>What a user would type at a prompt, e.g. <c>pktmon filter add "DNS" -t UDP -p 53</c>.</summary>
        public string DisplayText => Executable + (Args.Count > 0 ? " " + ArgumentString : "");

        public PktmonCommand WithNote(string note) => new PktmonCommand(Args, note, Executable);

        public override string ToString() => DisplayText;

        /// <summary>Quotes one argument per the MSVCRT/CommandLineToArgvW rules.</summary>
        public static string QuoteArg(string arg)
        {
            if (arg.Length > 0 && arg.IndexOfAny(new[] { ' ', '\t', '"', '&', '|', '<', '>', '^' }) < 0)
                return arg;

            var sb = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char c in arg)
            {
                if (c == '\\') { backslashes++; continue; }
                if (c == '"')
                {
                    sb.Append('\\', backslashes * 2 + 1);
                    sb.Append('"');
                }
                else
                {
                    sb.Append('\\', backslashes);
                    sb.Append(c);
                }
                backslashes = 0;
            }
            sb.Append('\\', backslashes * 2);
            sb.Append('"');
            return sb.ToString();
        }

        // ---- Builders -----------------------------------------------------------

        public static PktmonCommand Status() => new PktmonCommand(new[] { "status" });
        public static PktmonCommand Stop(string note = null) => new PktmonCommand(new[] { "stop" }, note);
        public static PktmonCommand Reset() => new PktmonCommand(new[] { "reset" }, "zeroes the counters of the running session");
        public static PktmonCommand Unload() => new PktmonCommand(new[] { "unload" });
        public static PktmonCommand Help() => new PktmonCommand(new[] { "help" });

        public static PktmonCommand List(bool all, bool includeHidden, bool json)
        {
            var a = new List<string> { "list" };
            if (all) a.Add("--all");
            if (includeHidden) a.Add("--include-hidden");
            if (json) a.Add("--json");
            return new PktmonCommand(a);
        }

        public static PktmonCommand FilterList() => new PktmonCommand(new[] { "filter", "list" });

        public static PktmonCommand FilterRemove(string note = null) =>
            new PktmonCommand(new[] { "filter", "remove" }, note);

        public static PktmonCommand FilterAdd(Model.FilterRule rule, string note = null) =>
            new PktmonCommand(new[] { "filter", "add" }.Concat(rule.ToArgs()), note);

        public static PktmonCommand Counters(string type = null, bool includeHidden = false, bool zero = false,
                                             bool dropReason = false, bool json = false)
        {
            var a = new List<string> { "counters" };
            if (!string.IsNullOrEmpty(type) && type != "all") { a.Add("--type"); a.Add(type); }
            if (includeHidden) a.Add("--include-hidden");
            if (zero) a.Add("--zero");
            if (dropReason) a.Add("--drop-reason");
            if (json) a.Add("--json");
            return new PktmonCommand(a);
        }

        public static PktmonCommand Start(Model.CaptureOptions o, string note = null) =>
            new PktmonCommand(new[] { "start" }.Concat(o.ToArgs()), note);

        public static PktmonCommand Etl2Pcap(string etl, string output, bool dropOnly, int? componentId)
        {
            var a = new List<string> { "etl2pcap", etl };
            if (!string.IsNullOrEmpty(output)) { a.Add("--out"); a.Add(output); }
            if (dropOnly) a.Add("--drop-only");
            if (componentId.HasValue) { a.Add("--component-id"); a.Add(componentId.Value.ToString()); }
            return new PktmonCommand(a, "the .etl is kept");
        }

        public static PktmonCommand Etl2Txt(string etl, string output, bool verbose, bool hex = false,
                                            bool timestamp = false, bool brief = false, bool stats = false)
        {
            var a = new List<string> { "etl2txt", etl };
            if (!string.IsNullOrEmpty(output)) { a.Add("--out"); a.Add(output); }
            if (stats) a.Add("--stats");
            if (timestamp) a.Add("--timestamp");
            if (brief) a.Add("--brief");
            if (verbose) a.Add("--verbose");
            if (hex) a.Add("--hex");
            return new PktmonCommand(a);
        }
    }
}
