using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using PktmonGUI.Pktmon;
using PktmonGUI.Services;

namespace PktmonGUI.Headless
{
    /// <summary>
    /// Headless mode's entry: parse, check, dispatch, exit. Work runs on pool threads (no
    /// SynchronizationContext, so services post nothing anywhere); the capture's mutex is taken and
    /// released on the main thread, which owns it.
    /// </summary>
    public static class HeadlessProgram
    {
        public static int Run(string[] args, bool noArguments)
        {
            int code;
            try { code = RunCore(args, noArguments); }
            catch (Exception ex)
            {
                try { new RunLog(HeadlessPaths.CliLog, null, null, Verbosity.Silent).Error("Unhandled: " + ex); } catch { }
                code = ExitCodes.Failed;
            }
            // A stray foreground thread must never keep a SYSTEM process alive.
            Environment.Exit(code);
            return code;
        }

        private static int RunCore(string[] args, bool noArguments)
        {
            if (noArguments)
            {
                var c = ConsoleOutput.Create(enabled: true);
                c.WriteLine("PktmonGUI's window can't open here: this session has no desktop (a service, WinRM or SCCM).");
                c.WriteLine("Run it with options instead:");
                c.WriteLine();
                c.WriteLine(Usage.Text);
                return ExitCodes.Usage;
            }

            var parsed = CliParser.Parse(args);
            if (!parsed.Ok)
            {
                var c = ConsoleOutput.Create(enabled: true);
                c.WriteLine("error: " + parsed.Error);
                try { new RunLog(HeadlessPaths.CliLog, null, null, Verbosity.Silent).Error($"{CaptureCommand.CommandLineText(args)}: {parsed.Error}"); } catch { }
                return ExitCodes.Usage;
            }

            var o = parsed.Options;
            var console = ConsoleOutput.Create(enabled: !o.DetachedChild);
            switch (o.Action)
            {
                case CliAction.Help:
                    console.WriteLine(Usage.Text);
                    return ExitCodes.Ok;
                case CliAction.Version:
                    console.WriteLine("PktmonGUI " + CaptureCommand.Version);
                    return ExitCodes.Ok;
            }

            if (o.LogFile != null)
            {
                // Every action appends to --log; check it before anything is written there.
                var logError = HeadlessPaths.PrepareOperatorFolder("--log", Path.GetDirectoryName(o.LogFile), o.Force);
                if (logError == null && !o.Force && File.Exists(o.LogFile) && (File.GetAttributes(o.LogFile) & FileAttributes.ReparsePoint) != 0)
                    logError = $"--log: {o.LogFile} is a link. Name a plain file, or add --force.";
                if (logError != null)
                {
                    o.LogFile = null;
                    return Fail(o, console, ExitCodes.Unsupported, logError);
                }
            }

            var envError = CheckEnvironment();
            if (envError != null)
            {
                if (o.Action == CliAction.Capture)
                    return new CaptureCommand(o, console).RunEnvironmentFailure(envError);
                return Fail(o, console, ExitCodes.Unsupported, envError);
            }

            // After the elevation check: a trusted settings.json copied in by an admin is handed to Administrators.
            var withDefaults = CliDefaults.Apply(args, o, SettingsTemplate.Read(AppDomain.CurrentDomain.BaseDirectory), out var settingsError);
            if (withDefaults == null) return Fail(o, console, ExitCodes.Usage, settingsError);
            o = withDefaults;

            try
            {
                switch (o.Action)
                {
                    case CliAction.Capture:
                        if (o.Detach) return RunAsync(() => Detacher.RunAsync(o, console));
                        return RunCapture(o, console);
                    case CliAction.Stop:
                        return RunAsync(() => StopCommand.RunAsync(o, console));
                    case CliAction.Status:
                        return RunAsync(() => StatusCommand.RunAsync(o, console));
                    case CliAction.Cleanup:
                        return RunAsync(() => CleanupCommand.RunAsync(o, console));
                    case CliAction.ListAdapters:
                        return RunAsync(() => ListAdaptersCommand.RunAsync(o, console));
                    default:
                        return Fail(o, console, ExitCodes.Usage, "Nothing to do.");
                }
            }
            catch (ForeignObjectException ex)
            {
                // Someone else created PktmonGUI's mutex or stop event (see SyncObjects).
                return Fail(o, console, ExitCodes.Unsupported, ex.Message);
            }
        }

        private static int RunCapture(HeadlessOptions o, ConsoleOutput console)
        {
            var capture = new CaptureCommand(o, console);
            Mutex created;
            try { created = SyncObjects.CreateMutex(); }
            catch (ForeignObjectException ex) { return capture.RunEnvironmentFailure(ex.Message); }
            using (var mutex = created)
            {
                bool abandoned = false, acquired;
                try { acquired = mutex.WaitOne(0); }
                catch (AbandonedMutexException) { acquired = true; abandoned = true; }
                if (!acquired)
                {
                    var state = HeadlessState.Load();
                    return capture.RunEnvironmentFailure(
                        "A headless capture is already running" + (state != null ? $" (PID {state.Pid}, started {state.StartedUtc.ToLocalTime():g})" : "") +
                        ". See PktmonGUI.exe --status; stop it with --stop.", ExitCodes.Busy);
                }
                AppDomain.CurrentDomain.UnhandledException += (s, e) => CaptureCommand.Current?.EmergencyStop(e.ExceptionObject as Exception ?? new Exception("unknown error"));
                TaskScheduler.UnobservedTaskException += (s, e) => e.SetObserved();
                try { return RunAsync(() => capture.RunAsync(abandoned)); }
                finally { try { mutex.ReleaseMutex(); } catch { } }
            }
        }

        private static int RunAsync(Func<Task<int>> body) => Task.Run(body).GetAwaiter().GetResult();

        /// <summary>Checks that need no state: elevation, Windows build, pktmon. Returns why not, or null.</summary>
        internal static string CheckEnvironment()
        {
            if (!SystemChecks.IsAdministrator())
                return "PktmonGUI must run elevated (as an administrator or SYSTEM).";
            var os = SystemChecks.OsInfo();
            if (os.build > 0 && os.build < SystemChecks.MinimumBuild)
                return $"{SystemChecks.OsText()} is too old: pktmon's real-time mode and current syntax need Windows 10 2004 / Server 2022 or later (build {SystemChecks.MinimumBuild}+).";
            if (!PktmonRunner.PktmonExists)
                return $"{PktmonRunner.PktmonPath} was not found.";
            return null;
        }

        /// <summary>Services for the non-capture actions, sharing the capture's settings and snapshots.</summary>
        internal static AppServices CreateServices(string workingFolder = null) =>
            new AppServices(null, new SettingsStore(HeadlessPaths.DataFolder, HeadlessPaths.SettingsFileName), workingFolder ?? HeadlessPaths.DataFolder);

        /// <summary>
        /// Prints what <see cref="HeadlessPaths.EnsureDataFolder"/> set aside, as a warning. With --json the
        /// command puts it in its JSON instead; cli.log has it either way.
        /// </summary>
        internal static void WarnSetAside(HeadlessOptions o, ConsoleOutput console)
        {
            if (HeadlessPaths.SetAsideNote != null && VerbosityOf(o) != Verbosity.Silent)
                console.WriteLine("warning: " + HeadlessPaths.SetAsideNote);
        }

        internal static Verbosity VerbosityOf(HeadlessOptions o) =>
            o.DetachedChild || o.Json ? Verbosity.Silent : o.Quiet ? Verbosity.Quiet : Verbosity.Normal;

        /// <summary>Prints an error (or its JSON), notes it in cli.log, and returns <paramref name="code"/>.</summary>
        internal static int Fail(HeadlessOptions o, ConsoleOutput console, int code, string message)
        {
            try { new RunLog(HeadlessPaths.CliLog, o.LogFile, null, Verbosity.Silent).Error($"{CaptureCommand.CommandLineText(o.RawArgs)}: {message}"); } catch { }
            if (o.Json) console.WriteLine(HeadlessJson.ToAscii(new { exitCode = code, meaning = ExitCodes.Describe(code), error = message }));
            else console.WriteLine((code == ExitCodes.Ok ? "" : "error: ") + message);
            return code;
        }
    }
}
