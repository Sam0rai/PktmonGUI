using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace PktmonGUI.Headless
{
    /// <summary>
    /// --stop: signals the running headless capture (possibly started by SYSTEM, or detached) and
    /// waits for it to finish converting, zipping and collecting. Exits with that capture's code.
    /// </summary>
    internal static class StopCommand
    {
        public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(15);

        public static async Task<int> RunAsync(HeadlessOptions o, ConsoleOutput console)
        {
            var timeout = o.Timeout ?? DefaultTimeout;
            var state = HeadlessState.Load();
            EventWaitHandle ev;
            try { ev = SyncObjects.TryOpenStopEvent(); }
            catch (UnauthorizedAccessException)
            {
                return HeadlessProgram.Fail(o, console, ExitCodes.Unsupported, "Access to the running capture's stop signal was denied: run elevated.");
            }

            if (ev == null)
            {
                if (state != null && !state.IsTerminal && !state.IsOwnerAlive())
                    return Report(o, console, ExitCodes.NothingToStop,
                        $"The headless capture started {state.StartedUtc.ToLocalTime():g} (PID {state.Pid}) is gone without finishing. Run PktmonGUI.exe --cleanup.", state);
                return Report(o, console, ExitCodes.NothingToStop, "No headless capture is running." + LastResultText(state), state);
            }

            using (ev)
            {
                ev.Set();
            }
            if (!o.Json && !o.Quiet)
                console.WriteLine($"Asked the headless capture{(state != null ? $" (PID {state.Pid})" : "")} to stop; waiting up to {DurationParser.Format(timeout)} for it to finish.");

            var deadline = DateTime.UtcNow + timeout;
            Process owner = null;
            try
            {
                if (state != null && state.IsOwnerAlive()) owner = Process.GetProcessById(state.Pid);
            }
            catch { owner = null; }

            using (owner)
            {
                while (DateTime.UtcNow < deadline)
                {
                    if (owner != null)
                    {
                        var left = deadline - DateTime.UtcNow;
                        if (owner.WaitForExit((int)Math.Min(1000, Math.Max(0, left.TotalMilliseconds)))) break;
                    }
                    else await Task.Delay(1000).ConfigureAwait(false);

                    var now = HeadlessState.Load();
                    if (now != null && now.Pid == state?.Pid && now.IsTerminal) break;
                    if (owner == null && SyncObjects.TryOpenStopEvent() is EventWaitHandle still) { still.Dispose(); continue; }
                    if (owner == null) break;
                }
            }

            var final = HeadlessState.Load();
            if (final != null && final.IsTerminal && final.LastResult != null && final.Pid == state?.Pid)
            {
                var r = final.LastResult;
                return Report(o, console, r.ExitCode ?? ExitCodes.Ok, ResultText(r), final);
            }
            return Report(o, console, ExitCodes.TimedOut,
                $"The capture is still finishing (phase {final?.Phase.ToString() ?? "unknown"}). Check again with PktmonGUI.exe --status.", final);
        }

        internal static string ResultText(RunResult r)
        {
            var s = $"{r.Status}: exit {r.ExitCode} ({r.Meaning})";
            if (r.StopReason != null) s += Environment.NewLine + "  Stopped " + r.StopReason;
            if (r.Counts?.PacketsTotal != null) s += Environment.NewLine + $"  Packets: {r.Counts.PacketsTotal:N0}";
            if (r.CollectedTo != null) s += Environment.NewLine + "  Copied to: " + r.CollectedTo;
            else if (r.Zip != null) s += Environment.NewLine + "  Zip: " + r.Zip;
            else if (r.RunFolder != null) s += Environment.NewLine + "  Files: " + r.RunFolder;
            foreach (var e in r.Errors) s += Environment.NewLine + "  error: " + e;
            if (r.Warnings.Count > 0) s += Environment.NewLine + $"  {r.Warnings.Count} warning(s); see result.json";
            return s;
        }

        private static string LastResultText(HeadlessState state) =>
            state?.LastResult == null ? "" : Environment.NewLine + "Last capture: " + ResultText(state.LastResult);

        private static int Report(HeadlessOptions o, ConsoleOutput console, int code, string text, HeadlessState state)
        {
            if (o.Json)
                console.WriteLine(HeadlessJson.ToAscii(new
                {
                    exitCode = code, meaning = ExitCodes.Describe(code), message = text,
                    phase = state?.Phase.ToString(), runFolder = state?.RunFolder, lastResult = state?.LastResult,
                }));
            else console.WriteLine(text);
            return code;
        }
    }
}
