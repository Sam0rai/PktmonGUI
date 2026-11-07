using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PktmonGUI.Model;
using PktmonGUI.Parsing;
using PktmonGUI.Pktmon;
using PktmonGUI.Services;

namespace PktmonGUI.Headless
{
    internal sealed class CleanupOutcome
    {
        public List<string> Done { get; } = new List<string>();
        public List<string> Problems { get; } = new List<string>();
        public bool ForeignSessionLeft { get; set; }
        public bool RestoreFailed { get; set; }
        public bool AdoptedSnapshot { get; set; }
    }

    /// <summary>
    /// --cleanup: puts the machine back after a headless capture that was killed. Only what is
    /// clearly a headless capture's is touched unless --force: this must be safe to run across a
    /// fleet without stopping another admin's or Defender's pktmon session.
    /// </summary>
    internal static class CleanupCommand
    {
        public static async Task<int> RunAsync(HeadlessOptions o, ConsoleOutput console)
        {
            var err = HeadlessPaths.EnsureDataFolder();
            if (err != null) return HeadlessProgram.Fail(o, console, ExitCodes.Unsupported, err);
            HeadlessProgram.WarnSetAside(o, console);
            if (SyncObjects.IsMutexHeld())
                return HeadlessProgram.Fail(o, console, ExitCodes.Busy, "A headless capture is running. Stop it with PktmonGUI.exe --stop; it cleans up after itself.");

            var log = new RunLog(HeadlessPaths.CliLog, o.LogFile, console, HeadlessProgram.VerbosityOf(o));
            log.Detail($"--- cleanup ({CaptureCommand.CommandLineText(o.RawArgs)}) as {SystemChecks.UserName()}");
            var s = HeadlessProgram.CreateServices();
            log.Attach(s.Log);

            var state = HeadlessState.Load();
            var outcome = await RecoverAsync(s, log, state, adopt: false, force: o.Force).ConfigureAwait(false);
            if (o.Purge) Purge(outcome, log);
            if (state != null && !state.IsTerminal)
            {
                state.Phase = RunPhase.CleanedUp;
                state.Save();
            }

            int code = outcome.RestoreFailed ? ExitCodes.NotRestored : outcome.ForeignSessionLeft ? ExitCodes.Busy : ExitCodes.Ok;
            if (o.Json)
            {
                console.WriteLine(HeadlessJson.ToAscii(new { exitCode = code, meaning = ExitCodes.Describe(code), done = outcome.Done, problems = outcome.Problems, setAside = HeadlessPaths.SetAsideNote }));
            }
            else
            {
                if (outcome.Done.Count == 0 && outcome.Problems.Count == 0) log.Final("Nothing to clean up: no leftovers from a headless capture.");
                else log.Final($"Cleanup: exit {code} ({ExitCodes.Describe(code)})");
            }
            return code;
        }

        /// <summary>
        /// Stops what a dead headless capture left running and deals with its filter snapshot.
        /// <paramref name="adopt"/> (a new capture recovering): the newest snapshot is restored when that
        /// capture ends. Otherwise (--cleanup): it's restored now, unless someone else's filters are on the
        /// machine by now (e.g. Defender re-added its own after a reboot) and <paramref name="force"/> isn't set.
        /// </summary>
        public static async Task<CleanupOutcome> RecoverAsync(AppServices s, RunLog log, HeadlessState stale, bool adopt, bool force)
        {
            var outcome = new CleanupOutcome();

            // pktmon keeps recording after its starter dies: Record mode lives in the driver.
            var st = StatusParser.Parse((await s.Runner.RunAsync(PktmonCommand.Status()).ConfigureAwait(false)).Output);
            if (st.Running)
            {
                bool ours = st.LogFile != null &&
                            (HeadlessPaths.IsUnder(st.LogFile, HeadlessPaths.RunsFolder) ||
                             (stale?.RunFolder != null && HeadlessPaths.IsUnder(st.LogFile, stale.RunFolder)));
                if (ours || force)
                {
                    var r = await s.Runner.RunAsync(PktmonCommand.Stop(ours ? "left running by a headless capture that didn't finish" : "--force")).ConfigureAwait(false);
                    if (r.Success) outcome.Done.Add($"Stopped the pktmon session {(ours ? "a headless capture left running" : "that was running")} ({st.LogFile ?? st.LogMode}).");
                    else outcome.Problems.Add("pktmon stop failed: " + r.Output);
                    if (ours && stale?.RunFolder != null && Directory.Exists(stale.RunFolder))
                        outcome.Done.Add($"Its recording is kept in {stale.RunFolder} (not converted or zipped).");
                }
                else
                {
                    outcome.ForeignSessionLeft = true;
                    outcome.Problems.Add($"A pktmon session that isn't a headless capture's is running ({st.LogMode ?? "unknown mode"}{(st.LogFile != null ? ", " + st.LogFile : "")}); left alone. --force stops it.");
                }
            }

            if (force || !CaptureCommand.OtherPktmonGuiRunning())
            {
                foreach (var name in SystemChecks.StopLeftoverEtwSessions()) outcome.Done.Add($"Stopped the leftover ETW session {name}.");
            }
            else if (SystemChecks.RunningEtwSessions().Count > 0)
                outcome.Problems.Add("PktmonGUI's ETW sessions are running, and so is a PktmonGUI that may own them; left alone. --force stops them.");

            var pending = s.Snapshots.FindUnrestored();
            if (adopt)
            {
                if (pending.Count > 0)
                {
                    s.Snapshots.Adopt(pending[0].Key, pending[0].Value);
                    outcome.AdoptedSnapshot = true;
                    outcome.Done.Add($"The machine's filters saved {pending[0].Value.Taken:g} ({pending[0].Value.Rules.Count} from {pending[0].Value.Owner}) will be put back when this capture ends.");
                }
                foreach (var older in pending.Skip(1))
                {
                    s.Snapshots.Dismiss(older.Key, older.Value);
                    outcome.Done.Add($"Set aside an older snapshot, {Path.GetFileName(older.Key)}.");
                }
            }
            else
            {
                MachineFilters current = null;
                try { current = await s.Filters.ReadAsync().ConfigureAwait(false); }
                catch (Exception ex) { outcome.Problems.Add("Couldn't read the machine's filters: " + ex.Message); }
                bool clearlyOurs = current != null && (current.AreOurs || current.Owner == "PktmonGUI");

                if (current != null && pending.Count > 0)
                {
                    var (path, snap) = (pending[0].Key, pending[0].Value);
                    if (current.Count == 0 || clearlyOurs || force)
                    {
                        var failures = await s.Snapshots.RestoreAsync(snap, path).ConfigureAwait(false);
                        if (failures.Count == 0)
                            outcome.Done.Add($"Put back the {snap.Rules.Count} filter(s) from {snap.Owner} that a headless capture had replaced (snapshot {Path.GetFileName(path)}).");
                        else
                        {
                            outcome.RestoreFailed = true;
                            outcome.Problems.Add($"Some filters from {Path.GetFileName(path)} couldn't be put back:\n" + string.Join("\n", failures));
                        }
                    }
                    else
                    {
                        outcome.RestoreFailed = true;
                        outcome.Problems.Add($"{current.Count} filter(s) from {current.Owner} are on the machine now, so the snapshot from {snap.Taken:g} " +
                                             $"({snap.Rules.Count} from {snap.Owner}) wasn't restored over them. --force restores it anyway. The snapshot is {path}.");
                    }
                    foreach (var older in pending.Skip(1))
                    {
                        s.Snapshots.Dismiss(older.Key, older.Value);
                        outcome.Done.Add($"Set aside an older snapshot, {Path.GetFileName(older.Key)}.");
                    }
                }
                else if (current != null && current.Count > 0 && clearlyOurs)
                {
                    var r = await s.Runner.RunAsync(PktmonCommand.FilterRemove("rules a headless capture left behind")).ConfigureAwait(false);
                    if (r.Success) outcome.Done.Add($"Removed the {current.Count} filter(s) a headless capture left on the machine.");
                    else { outcome.RestoreFailed = true; outcome.Problems.Add("pktmon filter remove failed: " + r.Output); }
                }
            }

            // Whatever was ours is gone or about to be replaced.
            s.Settings.AppliedFilterListRaw = null;
            s.Settings.AppliedRules = new List<FilterRule>();
            s.Store.Save();

            foreach (var d in outcome.Done) log.Info(d);
            foreach (var p in outcome.Problems) log.Warn(p);
            return outcome;
        }

        private static void Purge(CleanupOutcome outcome, RunLog log)
        {
            int runs = 0, copies = 0;
            try
            {
                if (Directory.Exists(HeadlessPaths.RunsFolder))
                {
                    foreach (var dir in Directory.GetDirectories(HeadlessPaths.RunsFolder)) { Directory.Delete(dir, true); runs++; }
                    foreach (var f in Directory.GetFiles(HeadlessPaths.RunsFolder)) { File.Delete(f); runs++; }
                }
            }
            catch (Exception ex) { outcome.Problems.Add("Couldn't delete every run: " + ex.Message); }
            try
            {
                string me;
                using (var p = Process.GetCurrentProcess()) me = p.MainModule.FileName;
                if (Directory.Exists(HeadlessPaths.BinFolder))
                    foreach (var f in Directory.GetFiles(HeadlessPaths.BinFolder, "*.exe"))
                    {
                        if (string.Equals(Path.GetFullPath(f), Path.GetFullPath(me), StringComparison.OrdinalIgnoreCase)) continue;
                        try { File.Delete(f); copies++; } catch { }
                    }
            }
            catch (Exception ex) { outcome.Problems.Add("Couldn't delete the exe copies: " + ex.Message); }
            var msg = $"Purged {runs} run(s) and {copies} copy(ies) of the exe under {HeadlessPaths.DataFolder}.";
            outcome.Done.Add(msg);
            log.Info(msg);
        }
    }
}
