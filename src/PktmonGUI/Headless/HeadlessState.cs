using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using PktmonGUI.Util;

namespace PktmonGUI.Headless
{
    public enum RunPhase { Starting, Running, Stopping, Finishing, Finished, Failed, Abandoned, CleanedUp }

    /// <summary>
    /// headless.json in %ProgramData%\PktmonGUI: the running (or last) headless capture. --stop,
    /// --status and a --detach parent read it; a non-terminal phase whose process is gone is the
    /// crash marker that recovery and --cleanup look for.
    /// </summary>
    public sealed class HeadlessState
    {
        public int Pid { get; set; }
        public DateTime ProcessStartUtc { get; set; }
        public string User { get; set; }
        public string CommandLine { get; set; }
        public RunPhase Phase { get; set; }
        public DateTime StartedUtc { get; set; }
        public DateTime? StopAtUtc { get; set; }
        public DateTime UpdatedUtc { get; set; }
        public string RunFolder { get; set; }
        public string EtlFile { get; set; }
        public string Zip { get; set; }
        public string CollectTo { get; set; }
        public RunResult LastResult { get; set; }

        public bool IsTerminal =>
            Phase == RunPhase.Finished || Phase == RunPhase.Failed || Phase == RunPhase.Abandoned || Phase == RunPhase.CleanedUp;

        public static HeadlessState Load(string path = null)
        {
            path = path ?? HeadlessPaths.StatePath;
            for (int attempt = 0; ; attempt++)
            {
                try { return Json.Load<HeadlessState>(path); }
                catch (IOException) when (attempt < 3) { Thread.Sleep(100); }
                catch (UnauthorizedAccessException) when (attempt < 3) { Thread.Sleep(100); }
                catch { return null; }
            }
        }

        public void Save(string path = null)
        {
            path = path ?? HeadlessPaths.StatePath;
            UpdatedUtc = DateTime.UtcNow;
            for (int attempt = 0; ; attempt++)
            {
                try { Json.Save(path, this); return; }
                catch (IOException) when (attempt < 5) { Thread.Sleep(100); }
                catch (UnauthorizedAccessException) when (attempt < 5) { Thread.Sleep(100); }
                catch { return; }
            }
        }

        /// <summary>This process, identified by PID and start time (PIDs are reused).</summary>
        public static HeadlessState ForCurrentProcess()
        {
            using (var p = Process.GetCurrentProcess())
                return new HeadlessState { Pid = p.Id, ProcessStartUtc = p.StartTime.ToUniversalTime() };
        }

        /// <summary>True while the process that wrote this state is still running.</summary>
        public bool IsOwnerAlive() => IsProcessAlive(Pid, ProcessStartUtc);

        public static bool IsProcessAlive(int pid, DateTime startUtc)
        {
            if (pid <= 0) return false;
            try
            {
                using (var p = Process.GetProcessById(pid))
                {
                    try { return Math.Abs((p.StartTime.ToUniversalTime() - startUtc).TotalSeconds) < 2; }
                    catch
                    {
                        // Can't read its start time: trust the name.
                        using (var me = Process.GetCurrentProcess())
                            return string.Equals(p.ProcessName, me.ProcessName, StringComparison.OrdinalIgnoreCase);
                    }
                }
            }
            catch { return false; }
        }
    }
}
