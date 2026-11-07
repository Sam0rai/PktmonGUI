using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PktmonGUI.Parsing;
using PktmonGUI.Pktmon;
using PktmonGUI.Util;

namespace PktmonGUI.Headless
{
    /// <summary>
    /// --detach: runs the capture in a new process that outlives this one. WinRM kills everything
    /// in a shell's job object when the session closes, and GPO startup scripts and SCCM programs
    /// have time limits; a detached capture is immune to both. This process returns once the
    /// capture is recording, having named the run folder itself so it can say where results go.
    /// </summary>
    internal static class Detacher
    {
        public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(60);

        public static async Task<int> RunAsync(HeadlessOptions o, ConsoleOutput console)
        {
            if (SyncObjects.IsMutexHeld())
                return HeadlessProgram.Fail(o, console, ExitCodes.Busy, "A headless capture is already running. See PktmonGUI.exe --status; stop it with --stop.");

            var err = HeadlessPaths.EnsureDataFolder();
            if (err != null) return HeadlessProgram.Fail(o, console, ExitCodes.Unsupported, err);
            HeadlessProgram.WarnSetAside(o, console);
            if (o.Out != null && (err = HeadlessPaths.CheckLocalDrive(o.Out)) != null) return HeadlessProgram.Fail(o, console, ExitCodes.Usage, "--out: " + err);
            if ((err = HeadlessPaths.PrepareOperatorFolder("--out", o.Out, o.Force)) != null ||
                (err = HeadlessPaths.PrepareOperatorFolder("--collect", o.Collect, o.Force)) != null)
                return HeadlessProgram.Fail(o, console, ExitCodes.Usage, err);

            if (!o.Force)
            {
                var runner = new PktmonRunner(new CommandLog(null), HeadlessPaths.DataFolder);
                var st = StatusParser.Parse((await runner.RunAsync(PktmonCommand.Status(), log: false).ConfigureAwait(false)).Output);
                if (st.Running && !(st.LogFile != null && HeadlessPaths.IsUnder(st.LogFile, HeadlessPaths.RunsFolder)))
                    return HeadlessProgram.Fail(o, console, ExitCodes.Busy,
                        $"A pktmon session is already running ({st.LogMode}{(st.LogFile != null ? ", " + st.LogFile : "")}). Stop it with 'pktmon stop', or add --force.");
            }

            var runFolder = HeadlessPaths.NewRunFolder(o.Out ?? HeadlessPaths.RunsFolder, Environment.MachineName, DateTime.Now);
            string exe;
            try { exe = LocalExe(); }
            catch (Exception ex) { return HeadlessProgram.Fail(o, console, ExitCodes.Failed, "Couldn't copy PktmonGUI.exe to a local folder: " + ex.Message); }

            var commandLine = PktmonCommand.QuoteArg(exe) + " " + BuildChildArgs(o.RawArgs, runFolder, CliDefaults.ChildMarker(o));
            int pid;
            string how;
            try { pid = Launch(commandLine, HeadlessPaths.DataFolder, out how); }
            catch (Exception ex) { return HeadlessProgram.Fail(o, console, ExitCodes.Failed, ex.Message); }

            Process child = null;
            try { child = Process.GetProcessById(pid); var _ = child.HasExited; } catch { child = null; }

            var deadline = DateTime.UtcNow + (o.Timeout ?? DefaultTimeout);
            using (child)
            {
                while (DateTime.UtcNow < deadline)
                {
                    var state = HeadlessState.Load();
                    if (state != null && state.Pid == pid && state.Phase == RunPhase.Running)
                        return Report(o, console, ExitCodes.Ok, pid, runFolder, state, how);

                    bool exited;
                    try { exited = child == null ? !IsAlive(pid) : child.HasExited; } catch { exited = true; }
                    if (exited)
                    {
                        int code = ExitCodes.Failed;
                        try { if (child != null) code = child.ExitCode; } catch { }
                        var result = HeadlessState.Load() is HeadlessState s2 && s2.Pid == pid ? s2.LastResult : null;
                        if (result == null)
                            try { result = Json.Load<RunResult>(Path.Combine(runFolder, "result.json")); } catch { }
                        if (result?.ExitCode != null) code = result.ExitCode.Value;
                        var msg = $"The capture process (PID {pid}) ended before recording: exit {code} ({ExitCodes.Describe(code)}).";
                        if (result != null && result.Errors.Count > 0) msg += Environment.NewLine + string.Join(Environment.NewLine, result.Errors.Select(e => "  error: " + e));
                        msg += Environment.NewLine + $"Details: {Path.Combine(runFolder, "run.log")} or {HeadlessPaths.CliLog}";
                        return HeadlessProgram.Fail(o, console, code == ExitCodes.Ok ? ExitCodes.Failed : code, msg);
                    }
                    await Task.Delay(250).ConfigureAwait(false);
                }
            }
            return HeadlessProgram.Fail(o, console, ExitCodes.TimedOut,
                $"The capture process (PID {pid}) didn't report recording within {DurationParser.Format(o.Timeout ?? DefaultTimeout)}. It may still start: check with PktmonGUI.exe --status. Run folder: {runFolder}");
        }

        private static int Report(HeadlessOptions o, ConsoleOutput console, int code, int pid, string runFolder, HeadlessState state, string how)
        {
            var stopAt = state.StopAtUtc?.ToLocalTime();
            var zip = HeadlessPaths.ZipPathFor(runFolder);
            if (o.Json)
            {
                console.WriteLine(HeadlessJson.ToAscii(new
                {
                    exitCode = code, meaning = "recording in the background", pid, runFolder, zip, stopAt,
                    collectTo = o.Collect, launchedVia = how, setAside = HeadlessPaths.SetAsideNote,
                }));
            }
            else if (!o.Quiet)
            {
                console.WriteLine($"Recording in the background (PID {pid}, started via {how}).");
                console.WriteLine("  Run folder: " + runFolder);
                console.WriteLine("  " + (stopAt.HasValue ? $"Stops at {stopAt:g}" : "Runs until stopped") + "; stop it sooner with: PktmonGUI.exe --stop");
                console.WriteLine("  Result: " + (o.Collect != null ? $"{zip}, copied to {o.Collect}" : zip));
            }
            return code;
        }

        /// <summary>
        /// The child's arguments: the same as ours without --detach and --timeout, plus the hidden
        /// markers. Walks the arguments with the parser's table so a --filter value is never mistaken for a flag.
        /// The defaults from settings.json are already in <paramref name="raw"/>; the child, which may run from a
        /// copy with no settings.json beside it, doesn't read one but is told where they came from.
        /// </summary>
        public static string BuildChildArgs(IReadOnlyList<string> raw, string runFolder, string settingsFrom = null)
        {
            var args = new List<string>();
            for (int i = 0; i < raw.Count; i++)
            {
                var token = raw[i];
                var name = token.Contains("=") ? token.Substring(0, token.IndexOf('=')) : token;
                bool inlineValue = token.Contains("=");
                bool takesValue = CliParser.TakesValue(name) && !inlineValue;
                bool drop = name.Equals("--detach", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("--timeout", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("--detached-child", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("--run-folder", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("--no-settings", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("--settings-from", StringComparison.OrdinalIgnoreCase);
                if (!drop) args.Add(token);
                if (takesValue && i + 1 < raw.Count)
                {
                    i++;
                    if (!drop) args.Add(raw[i]);
                }
            }
            args.Add("--detached-child");
            args.Add("--run-folder");
            args.Add(runFolder);
            if (settingsFrom != null) { args.Add("--settings-from"); args.Add(settingsFrom); }
            else args.Add("--no-settings");
            return string.Join(" ", args.Select(PktmonCommand.QuoteArg));
        }

        /// <summary>
        /// The exe the child runs from. From a share (UNC, SYSVOL), a copy under %ProgramData%\PktmonGUI\bin:
        /// a network path can vanish mid-capture, and a network logon's child can't read it at all.
        /// </summary>
        private static string LocalExe()
        {
            string me;
            using (var p = Process.GetCurrentProcess()) me = p.MainModule.FileName;
            var root = Path.GetPathRoot(me) ?? "";
            if (!root.StartsWith(@"\\", StringComparison.Ordinal))
            {
                try
                {
                    var type = new DriveInfo(root).DriveType;
                    if (type == DriveType.Fixed || type == DriveType.Removable) return me;
                }
                catch { }
            }
            Directory.CreateDirectory(HeadlessPaths.BinFolder);
            var target = Path.Combine(HeadlessPaths.BinFolder, "PktmonGUI.exe");
            if (File.Exists(target) && SameFile(me, target)) return target;
            try { File.Copy(me, target, overwrite: true); return target; }
            catch (IOException)
            {
                // In use by a running capture: keep that one, use a fresh copy.
                var alt = Path.Combine(HeadlessPaths.BinFolder, $"PktmonGUI-{DateTime.Now:yyyyMMddHHmmss}.exe");
                File.Copy(me, alt, overwrite: true);
                return alt;
            }
        }

        private static bool SameFile(string a, string b)
        {
            try
            {
                if (new FileInfo(a).Length != new FileInfo(b).Length) return false;
                using (var sha = SHA256.Create())
                using (var fa = File.OpenRead(a))
                using (var fb = File.OpenRead(b))
                {
                    var ha = sha.ComputeHash(fa);
                    return ha.SequenceEqual(sha.ComputeHash(fb));
                }
            }
            catch { return false; }
        }

        /// <summary>Starts the child outside our job object. Returns its PID.</summary>
        private static int Launch(string commandLine, string workingDir, out string how)
        {
            string wmiError;
            try
            {
                how = "WMI";
                return LaunchViaWmi(commandLine, workingDir);
            }
            catch (Exception ex) { wmiError = ex.Message; }

            bool inJob = false;
            try
            {
                using (var me = Process.GetCurrentProcess())
                    HeadlessNative.IsProcessInJob(me.Handle, IntPtr.Zero, out inJob);
            }
            catch { }
            try
            {
                how = inJob ? "CreateProcess (breakaway from the job)" : "CreateProcess";
                return LaunchDirect(commandLine, workingDir, breakaway: inJob);
            }
            catch (Exception ex)
            {
                if (inJob)
                    throw new InvalidOperationException(
                        $"Couldn't start the capture outside this session's job, so it would end with the session. WMI: {wmiError}. " +
                        $"Breakaway: {ex.Message}. Run without --detach, or start it from a scheduled task.");
                throw new InvalidOperationException($"Couldn't start the capture process. WMI: {wmiError}. CreateProcess: {ex.Message}");
            }
        }

        /// <summary>
        /// Win32_Process.Create: the child's parent is WmiPrvSE, outside WinRM's job object, with our identity.
        /// (The Defender ASR rule "Block process creations originating from PSExec and WMI commands" blocks this.)
        /// </summary>
        private static int LaunchViaWmi(string commandLine, string workingDir)
        {
            using (var process = new ManagementClass(@"\\.\root\cimv2", "Win32_Process", null))
            using (var startupClass = new ManagementClass(@"\\.\root\cimv2", "Win32_ProcessStartup", null))
            using (var startup = startupClass.CreateInstance())
            using (var input = process.GetMethodParameters("Create"))
            {
                startup["ShowWindow"] = (ushort)0; // SW_HIDE
                startup["CreateFlags"] = HeadlessNative.CREATE_NEW_PROCESS_GROUP;
                input["CommandLine"] = commandLine;
                input["CurrentDirectory"] = workingDir;
                input["ProcessStartupInformation"] = startup;
                using (var output = process.InvokeMethod("Create", input, null))
                {
                    var rv = Convert.ToUInt32(output["ReturnValue"]);
                    if (rv != 0) throw new InvalidOperationException($"Win32_Process.Create returned {rv} ({WmiError(rv)})");
                    return Convert.ToInt32(output["ProcessId"]);
                }
            }
        }

        private static string WmiError(uint rv)
        {
            switch (rv)
            {
                case 2: return "access denied";
                case 3: return "insufficient privilege";
                case 8: return "unknown failure";
                case 9: return "path not found";
                case 21: return "invalid parameter";
                default: return "error";
            }
        }

        /// <summary>
        /// CreateProcess with bInheritHandles FALSE: an inherited stdout pipe would keep a remote
        /// PowerShell pipeline waiting until the capture ends.
        /// </summary>
        private static int LaunchDirect(string commandLine, string workingDir, bool breakaway)
        {
            var si = new HeadlessNative.STARTUPINFO { cb = System.Runtime.InteropServices.Marshal.SizeOf(typeof(HeadlessNative.STARTUPINFO)) };
            si.dwFlags = HeadlessNative.STARTF_USESHOWWINDOW;
            si.wShowWindow = 0;
            uint flags = HeadlessNative.CREATE_NEW_PROCESS_GROUP | HeadlessNative.CREATE_NO_WINDOW | HeadlessNative.CREATE_UNICODE_ENVIRONMENT;
            if (breakaway) flags |= HeadlessNative.CREATE_BREAKAWAY_FROM_JOB;
            var cmd = new StringBuilder(commandLine);
            if (!HeadlessNative.CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, workingDir, ref si, out var pi))
                throw new Win32Exception();
            HeadlessNative.CloseHandle(pi.hThread);
            HeadlessNative.CloseHandle(pi.hProcess);
            return pi.dwProcessId;
        }

        private static bool IsAlive(int pid)
        {
            try { using (var p = Process.GetProcessById(pid)) return !p.HasExited; }
            catch { return false; }
        }
    }
}
