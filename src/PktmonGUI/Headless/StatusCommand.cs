using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PktmonGUI.Parsing;
using PktmonGUI.Pktmon;

namespace PktmonGUI.Headless
{
    /// <summary>--status: the running capture, pktmon's own state, leftovers, and the last result.</summary>
    internal static class StatusCommand
    {
        public sealed class StatusReport
        {
            /// <summary>running, idle, or stale (a capture died without finishing).</summary>
            public string Headless { get; set; }
            public int? Pid { get; set; }
            public string Phase { get; set; }
            public string RunFolder { get; set; }
            public DateTime? Started { get; set; }
            public DateTime? StopAt { get; set; }
            public string Elapsed { get; set; }
            public long? EtlBytes { get; set; }
            public bool PktmonRunning { get; set; }
            public string PktmonLogFile { get; set; }
            public string PktmonLogMode { get; set; }
            public bool? PktmonSessionIsHeadless { get; set; }
            public int MachineFilters { get; set; }
            public string MachineFiltersOwner { get; set; }
            public List<string> Leftovers { get; set; } = new List<string>();
            public List<string> RecentZips { get; set; } = new List<string>();
            public RunResult LastResult { get; set; }
            public int ExitCode { get; set; }
            public string Meaning { get; set; }
            /// <summary>An unsafe %ProgramData%\PktmonGUI this command renamed aside and made again; null if none.</summary>
            public string SetAside { get; set; }
        }

        public static async Task<int> RunAsync(HeadlessOptions o, ConsoleOutput console)
        {
            var err = HeadlessPaths.EnsureDataFolder();
            if (err != null) return HeadlessProgram.Fail(o, console, ExitCodes.Unsupported, err);
            HeadlessProgram.WarnSetAside(o, console);
            var s = HeadlessProgram.CreateServices();
            var state = HeadlessState.Load();
            var r = new StatusReport { LastResult = state?.LastResult, SetAside = HeadlessPaths.SetAsideNote };

            bool alive = state != null && !state.IsTerminal && state.IsOwnerAlive();
            bool stale = state != null && !state.IsTerminal && !alive;
            r.Headless = alive ? "running" : stale ? "stale" : "idle";
            if (state != null && (alive || stale))
            {
                r.Pid = state.Pid;
                r.Phase = state.Phase.ToString();
                r.RunFolder = state.RunFolder;
                r.Started = state.StartedUtc.ToLocalTime();
                r.StopAt = state.StopAtUtc?.ToLocalTime();
                r.Elapsed = DurationParser.Format(DateTime.UtcNow - state.StartedUtc);
                try { if (state.RunFolder != null && Directory.Exists(state.RunFolder)) r.EtlBytes = Directory.GetFiles(state.RunFolder, "*.etl").Sum(f => new FileInfo(f).Length); } catch { }
                if (stale) r.Leftovers.Add($"The headless capture started {r.Started:g} (PID {state.Pid}) died without finishing.");
            }

            var st = StatusParser.Parse((await s.Runner.RunAsync(PktmonCommand.Status(), log: false).ConfigureAwait(false)).Output);
            r.PktmonRunning = st.Running;
            if (st.Running)
            {
                r.PktmonLogFile = st.LogFile;
                r.PktmonLogMode = st.LogMode;
                bool headless = st.LogFile != null && (HeadlessPaths.IsUnder(st.LogFile, HeadlessPaths.RunsFolder) ||
                                                       (state?.RunFolder != null && HeadlessPaths.IsUnder(st.LogFile, state.RunFolder)));
                r.PktmonSessionIsHeadless = headless;
                if (headless && !alive) r.Leftovers.Add($"pktmon is still recording to {st.LogFile}, and no headless capture owns it.");
            }

            bool otherGui = CaptureCommand.OtherPktmonGuiRunning();
            if (!alive && !otherGui)
                foreach (var name in Services.SystemChecks.RunningEtwSessions()) r.Leftovers.Add($"The ETW session {name} is still running.");

            if (!alive)
            {
                foreach (var kv in s.Snapshots.FindUnrestored())
                    r.Leftovers.Add($"The machine's filters saved {kv.Value.Taken:g} ({kv.Value.Rules.Count} from {kv.Value.Owner}) were never put back: {kv.Key}");
            }
            try
            {
                var f = await s.Filters.ReadAsync(log: false).ConfigureAwait(false);
                r.MachineFilters = f.Count;
                r.MachineFiltersOwner = f.Count > 0 ? (f.AreOurs ? "PktmonGUI" : f.Owner) : null;
                if (!alive && f.Count > 0 && (f.AreOurs || f.Owner == "PktmonGUI"))
                    r.Leftovers.Add($"{f.Count} filter(s) a headless capture set are still on the machine.");
            }
            catch { }

            try
            {
                if (Directory.Exists(HeadlessPaths.RunsFolder))
                    r.RecentZips = new DirectoryInfo(HeadlessPaths.RunsFolder).GetFiles("*.zip").OrderByDescending(f => f.LastWriteTimeUtc).Take(5)
                        .Select(f => $"{f.FullName} ({CaptureCommand.Bytes(f.Length)}, {f.LastWriteTime:g})").ToList();
            }
            catch { }

            r.ExitCode = alive ? ExitCodes.Busy : r.Leftovers.Count > 0 ? ExitCodes.NothingToStop : ExitCodes.Ok;
            r.Meaning = alive ? "a headless capture is running" : r.Leftovers.Count > 0 ? "leftovers found: run --cleanup" : "idle";

            if (o.Json) console.WriteLine(HeadlessJson.ToAscii(r));
            else console.WriteLine(Text(r));
            return r.ExitCode;
        }

        private static string Text(StatusReport r)
        {
            var lines = new List<string>();
            switch (r.Headless)
            {
                case "running":
                    lines.Add($"Headless capture: running (PID {r.Pid}, {r.Phase}), started {r.Started:g}, {r.Elapsed} ago" +
                              (r.StopAt.HasValue ? $", stops {r.StopAt:g}" : ", until stopped"));
                    lines.Add($"  Recording to {r.RunFolder}" + (r.EtlBytes.HasValue ? $" ({CaptureCommand.Bytes(r.EtlBytes.Value)} so far)" : ""));
                    lines.Add("  Stop it with: PktmonGUI.exe --stop");
                    break;
                case "stale":
                    lines.Add($"Headless capture: died without finishing (PID {r.Pid}, {r.Phase}), started {r.Started:g}");
                    break;
                default:
                    lines.Add("Headless capture: none running");
                    break;
            }
            lines.Add(r.PktmonRunning
                ? $"pktmon: running ({r.PktmonLogMode}{(r.PktmonLogFile != null ? ", " + r.PktmonLogFile : "")})" +
                  (r.PktmonSessionIsHeadless == true ? "" : " (not a headless capture's)")
                : "pktmon: not running");
            lines.Add(r.MachineFilters == 0 ? "Machine filters: none" : $"Machine filters: {r.MachineFilters} from {r.MachineFiltersOwner}");
            if (r.Leftovers.Count > 0)
            {
                lines.Add("Leftovers (fix with PktmonGUI.exe --cleanup):");
                lines.AddRange(r.Leftovers.Select(l => "  - " + l));
            }
            if (r.LastResult != null && r.Headless != "running")
                lines.Add("Last capture: " + StopCommand.ResultText(r.LastResult).Replace(Environment.NewLine, Environment.NewLine + "  "));
            if (r.RecentZips.Count > 0)
            {
                lines.Add("Recent results:");
                lines.AddRange(r.RecentZips.Select(z => "  " + z));
            }
            return string.Join(Environment.NewLine, lines);
        }
    }
}
