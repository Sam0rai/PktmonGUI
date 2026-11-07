using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using PktmonGUI.Attribution;
using PktmonGUI.Model;
using PktmonGUI.Parsing;
using PktmonGUI.Pktmon;
using PktmonGUI.Services;
using PktmonGUI.Util;

namespace PktmonGUI.Headless
{
    /// <summary>
    /// One headless capture, start to finish: check, apply filters, record (Record mode, with process
    /// attribution), wait for a stop signal, stop, put the machine back, convert to pcapng, zip, and
    /// optionally copy the zip to a share. The machine is restored before any slow work, and on every
    /// path out (see <see cref="EnsureMachineRestoredAsync"/> and <see cref="EmergencyStop"/>).
    /// </summary>
    internal sealed class CaptureCommand
    {
        private static readonly long LowDiskBytes = 1L << 30;

        /// <summary>The capture running in this process, for the crash handler.</summary>
        public static CaptureCommand Current { get; private set; }

        private readonly HeadlessOptions _o;
        private readonly ConsoleOutput _console;
        private readonly object _gate = new object();
        private readonly List<int> _codes = new List<int>();
        private readonly string _host = Environment.MachineName;

        private RunLog _log;
        private RunResult _result;
        private HeadlessState _state;
        private AppServices _s;
        private StopSignals _signals;
        private string _runFolder, _runName, _zip, _etl;
        private StopReason _reason;
        private bool _captureStarted, _filtersTouched, _restoreDone;
        /// <summary>--out was refused: nothing may be written under it, not even the early-exit result.</summary>
        private bool _outUnsafe;
        private int _emergency;

        public CaptureCommand(HeadlessOptions o, ConsoleOutput console)
        {
            _o = o;
            _console = console;
        }

        public static string Version => "v" + Assembly.GetExecutingAssembly().GetName().Version.ToString(3);

        private Verbosity Verbosity => _o.DetachedChild || _o.Json ? Verbosity.Silent : _o.Quiet ? Verbosity.Quiet : Verbosity.Normal;

        // ---- Entry -----------------------------------------------------------------------

        public async Task<int> RunAsync(bool previousAbandoned)
        {
            Current = this;
            var started = DateTimeOffset.Now;

            var err = HeadlessPaths.EnsureDataFolder();
            if (err != null) return EarlyExit(ExitCodes.Unsupported, err);
            var outDir = _o.Out ?? HeadlessPaths.RunsFolder;
            if (_o.Out != null && (err = HeadlessPaths.CheckLocalDrive(_o.Out)) != null) return EarlyExit(ExitCodes.Usage, "--out: " + err);
            if ((err = HeadlessPaths.PrepareOperatorFolder("--out", _o.Out, _o.Force)) != null)
            {
                _outUnsafe = true;
                return EarlyExit(ExitCodes.Usage, err);
            }
            if ((err = HeadlessPaths.PrepareOperatorFolder("--collect", _o.Collect, _o.Force)) != null) return EarlyExit(ExitCodes.Usage, err);

            _runFolder = _o.RunFolder ?? HeadlessPaths.NewRunFolder(outDir, _host, started.LocalDateTime);
            _runName = Path.GetFileName(_runFolder.TrimEnd('\\', '/'));
            _zip = HeadlessPaths.ZipPathFor(_runFolder);
            if ((err = CreateRunFolder(_runFolder, out var runAside)) != null) return EarlyExit(ExitCodes.Unsupported, err);

            _log = new RunLog(Path.Combine(_runFolder, "run.log"), _o.LogFile, _console, Verbosity);
            _result = new RunResult
            {
                Status = "Starting", Host = _host, User = SystemChecks.UserName(), Version = Version,
                CommandLine = CommandLineText(_o.RawArgs), Pid = Process.GetCurrentProcess().Id,
                Started = started, RunFolder = _runFolder, Zip = _zip,
                Settings = _o.SettingsFile == null ? null : new RunResult.SettingsInfo { File = _o.SettingsFile, Applied = _o.SettingsApplied.ToList() },
            };
            SaveResult();
            _log.Info($"PktmonGUI {Version} headless capture on {_host} as {_result.User} ({SystemChecks.OsText()})");
            _log.Detail("Command line: " + _result.CommandLine);
            _log.Detail("Run folder: " + _runFolder);
            if (_o.SettingsFile != null)
                _log.Info($"Defaults from {_o.SettingsFile}: " + (_o.SettingsApplied.Count > 0 ? string.Join(", ", _o.SettingsApplied) : "none needed (the command line gave them)"));
            if (HeadlessPaths.SetAsideNote != null) Warn(HeadlessPaths.SetAsideNote);
            if (runAside != null) Warn(runAside);
            if (previousAbandoned) Warn("The previous headless capture ended abnormally (it never released its lock).");

            var rules = HeadlessFilters.Build(_o, File.ReadAllText, out err);
            if (rules == null) return await FinishAsync("Failed", ExitCodes.Usage, err).ConfigureAwait(false);

            _s = new AppServices(null, new SettingsStore(HeadlessPaths.DataFolder, HeadlessPaths.SettingsFileName), _runFolder);
            _log.Attach(_s.Log);

            // A capture that died without finishing left pktmon, ETW sessions or replaced filters behind.
            var stale = HeadlessState.Load();
            if (stale != null && !stale.IsTerminal && !stale.IsOwnerAlive())
            {
                Warn($"The headless capture started {stale.StartedUtc.ToLocalTime():g} (PID {stale.Pid}) never finished; cleaning up after it first.");
                var rec = await CleanupCommand.RecoverAsync(_s, _log, stale, adopt: true, force: false).ConfigureAwait(false);
                if (rec.AdoptedSnapshot) _filtersTouched = true;
                stale.Phase = RunPhase.Abandoned;
                stale.Save();
            }

            _state = HeadlessState.ForCurrentProcess();
            _state.User = _result.User;
            _state.CommandLine = _result.CommandLine;
            _state.Phase = RunPhase.Starting;
            _state.StartedUtc = started.UtcDateTime;
            _state.RunFolder = _runFolder;
            _state.Zip = _zip;
            _state.CollectTo = _o.Collect;
            _state.Save();

            // Before anything on the machine changes: a stop event someone else created ends the run here.
            EventWaitHandle created;
            try { created = SyncObjects.CreateStopEvent(); }
            catch (ForeignObjectException ex) { return await FinishAsync("Failed", ExitCodes.Unsupported, ex.Message).ConfigureAwait(false); }
            using (var stopEvent = created)
            using (_signals = new StopSignals())
            using (var awake = KeepAwake.Start("PktmonGUI headless capture: recording, converting and zipping", out var awakeError))
            {
                if (awake == null) Warn($"Couldn't keep Windows awake during the capture ({awakeError}); it stops if the machine goes to sleep.");
                _signals.WatchStopEvent(stopEvent);
                if (_console.IsAttachedToConsole) _signals.HookConsole();
                try
                {
                    return await CaptureAsync(rules).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    return await FinishAsync("Failed", ExitCodes.Failed, "Unexpected error: " + ex).ConfigureAwait(false);
                }
            }
        }

        private async Task<int> CaptureAsync(List<FilterRule> rules)
        {
            // ---- pktmon ------------------------------------------------------------------
            var statusRun = await _s.Runner.RunAsync(PktmonCommand.Status()).ConfigureAwait(false);
            if (statusRun.Output.IndexOf("Access is denied", StringComparison.OrdinalIgnoreCase) >= 0)
                return await FinishAsync("Failed", ExitCodes.Unsupported, "pktmon status was denied: PktmonGUI must run elevated.").ConfigureAwait(false);
            var status = StatusParser.Parse(statusRun.Output);
            if (status.Running)
            {
                var desc = $"{status.LogMode ?? "unknown mode"}{(status.LogFile != null ? ", " + status.LogFile : "")}";
                if (IsHeadlessLogFile(status.LogFile))
                {
                    Warn($"A headless capture that no process owns is still recording ({desc}); stopping it.");
                    await _s.Runner.RunAsync(PktmonCommand.Stop("orphaned headless capture")).ConfigureAwait(false);
                }
                else if (_o.Force)
                {
                    Warn($"Stopping the pktmon session that was already running ({desc}), as --force asks.");
                    await _s.Runner.RunAsync(PktmonCommand.Stop("--force: the session was already running")).ConfigureAwait(false);
                }
                else
                    return await FinishAsync("Failed", ExitCodes.Busy,
                        $"A pktmon session is already running ({desc}). pktmon allows one at a time. Stop it with 'pktmon stop', or run again with --force.").ConfigureAwait(false);
            }
            if (OtherPktmonGuiRunning()) Warn("Another PktmonGUI is running; its ETW sessions are left alone.");
            else foreach (var name in SystemChecks.StopLeftoverEtwSessions()) Warn($"Stopped the leftover ETW session {name}.");

            // ---- Disk and destination --------------------------------------------------------
            var free = SystemChecks.FreeBytes(_runFolder);
            long need = ((long)_o.FileSizeMb << 20) + LowDiskBytes;
            if (free.HasValue && free.Value < need)
                return await FinishAsync("Failed", ExitCodes.Unsupported,
                    $"Only {Bytes(free.Value)} free for {_runFolder}; this capture needs at least {Bytes(need)} (the file size plus 1 GB).").ConfigureAwait(false);
            if (free.HasValue && free.Value < 3L * ((long)_o.FileSizeMb << 20))
                Warn($"Only {Bytes(free.Value)} free: the .etl, the .pcapng and the zip need room at the same time.");
            if (_o.Collect != null) ProbeCollect();

            // ---- Components ----------------------------------------------------------------
            List<Component> all;
            try { all = await _s.Components.LoadAsync(includeAll: true).ConfigureAwait(false); }
            catch (Exception ex) { return await FinishAsync("Failed", ExitCodes.Failed, "pktmon list failed: " + ex.Message).ConfigureAwait(false); }
            var sel = ComponentSelector.Resolve(_o.Components, all, () => _s.Components.PickDefaults(new string[0]));
            WriteText("components.txt", ListAdaptersCommand.Table(all.Where(c => c.IsAdapter),
                c => sel.AllNics || sel.Components.Any(x => x.Id == c.Id)) + Environment.NewLine + "Selected: " + (sel.Ok ? sel.Describe() : sel.Error));
            if (!sel.Ok) return await FinishAsync("Failed", ExitCodes.Usage, sel.Error).ConfigureAwait(false);
            _log.Info("Capturing on " + sel.Describe());
            if (sel.Components.Any(c => c.IsWireless))
                Warn("A selected adapter is wireless: pktmon records Wi-Fi traffic, but etl2pcap's output may not open cleanly in Wireshark.");

            // ---- Filters -------------------------------------------------------------------
            var filters = new RunResult.FiltersInfo();
            _result.Filters = filters;
            List<FilterRule> ruleSet;
            try
            {
                var before = await _s.Filters.ReadAsync().ConfigureAwait(false);
                WriteText("filters-before.txt", before.Raw);
                filters.ForeignCount = before.HasForeign ? before.Count : 0;
                filters.ForeignOwner = before.HasForeign ? before.Owner : null;
                if (_o.KeepFilters)
                {
                    filters.Mode = "kept";
                    ruleSet = before.Filters.Select(f => f.Rule).ToList();
                    if (before.HasForeign) Warn($"Capturing through {before.Count} filter(s) from {before.Owner}, unchanged (--keep-filters).");
                }
                else if (rules.Count > 0)
                {
                    _filtersTouched = true;
                    await _s.Filters.ApplyAsync(rules, snapshotForeign: true, restoreOnStop: true).ConfigureAwait(false);
                    filters.Mode = before.HasForeign ? "replaced-foreign" : "applied";
                    ruleSet = rules;
                    if (before.HasForeign) Warn($"Replaced {before.Count} filter(s) from {before.Owner} for this capture; they're put back when it ends.");
                }
                else if (before.Count > 0)
                {
                    _filtersTouched = true;
                    await _s.Filters.ClearAsync(snapshotForeign: true, restoreOnStop: true).ConfigureAwait(false);
                    filters.Mode = before.HasForeign ? "cleared-foreign" : "cleared";
                    ruleSet = new List<FilterRule>();
                    if (before.HasForeign) Warn($"Cleared {before.Count} filter(s) from {before.Owner} so the capture sees every packet; they're put back when it ends. Use --keep-filters to capture through them instead.");
                }
                else
                {
                    filters.Mode = "none";
                    ruleSet = new List<FilterRule>();
                }
                filters.Rules = ruleSet.Select(r => (r.Name != null ? r.Name + ": " : "") + r.ArgsSummary).ToList();
                filters.Snapshot = _s.Snapshots.ActivePath;
            }
            catch (Exception ex)
            {
                return await FinishAsync("Failed", ExitCodes.Failed, "Couldn't set the capture's filters: " + ex.Message).ConfigureAwait(false);
            }

            // ---- Start ---------------------------------------------------------------------
            _etl = Path.Combine(_runFolder, _runName + ".etl");
            var options = new CaptureOptions
            {
                Mode = CaptureMode.Record,
                AllNics = sel.AllNics,
                ComponentIds = sel.Components.Select(c => c.Id).ToList(),
                Type = _o.Type,
                PacketSize = _o.PacketSize,
                FileName = _etl,
                FileSizeMb = _o.FileSizeMb,
                LogMode = _o.LogMode,
            };
            var invalid = options.Validate().FirstOrDefault();
            if (invalid != null) return await FinishAsync("Failed", ExitCodes.Usage, invalid).ConfigureAwait(false);

            var duration = _o.EffectiveDuration;
            _result.Capture = new RunResult.CaptureInfo
            {
                StartCommand = PktmonCommand.Start(options).DisplayText,
                AllNics = sel.AllNics,
                Components = sel.AllNics ? new List<string> { "all network adapters" }
                                         : sel.Components.Select(c => $"{c.ConnectionName ?? c.Name} (id {c.Id}, {c.MacAddress})").ToList(),
                PacketSize = options.PacketSize,
                FileSizeMb = options.FileSizeMb,
                LogMode = CaptureOptions.LogModeArg(options.LogMode),
                Type = options.Type.ToString().ToLowerInvariant(),
                Attribution = !_o.NoAttribution,
                Duration = duration.HasValue ? DurationParser.Format(duration.Value) : "until stopped",
            };

            if (_signals.Stopped.IsCompleted)
                return await FinishAsync("Cancelled", ExitCodes.Warnings, "Stopped before the capture started.").ConfigureAwait(false);

            try
            {
                await _s.Session.StartAsync(options, all, ruleSet, attributeProcesses: !_o.NoAttribution).ConfigureAwait(false);
                _captureStarted = true;
            }
            catch (Exception ex)
            {
                return await FinishAsync("Failed", ExitCodes.Failed, "pktmon didn't start: " + ex.Message).ConfigureAwait(false);
            }
            if (_s.Session.Attribution?.EtwError != null)
                Warn("Process attribution runs without ETW (" + _s.Session.Attribution.EtwError + "); using the connection tables only.");

            _state.Phase = RunPhase.Running;
            _state.EtlFile = _etl;
            _state.StopAtUtc = duration.HasValue ? DateTime.UtcNow + duration.Value : (DateTime?)null;
            _state.Save();
            _result.Status = "Running";
            SaveResult();
            _log.Info($"Recording to {_etl}; " +
                      (duration.HasValue ? $"stops after {DurationParser.Format(duration.Value)}" : "runs until stopped") +
                      ". Stop it with: PktmonGUI.exe --stop");

            // ---- Wait ----------------------------------------------------------------------
            _signals.StartDuration(duration);
            using (var monitorCts = new CancellationTokenSource())
            {
                var monitor = MonitorAsync(monitorCts.Token);
                _reason = await _signals.Stopped.ConfigureAwait(false);
                monitorCts.Cancel();
                try { await monitor.ConfigureAwait(false); } catch { }
            }
            _result.StopReason = Describe(_reason, duration);
            _log.Info("Stopping " + _result.StopReason + ".");
            if (_reason == StopReason.PktmonEndedExternally || _reason == StopReason.LowDisk) { Warn("The capture stopped " + _result.StopReason + "."); AddCode(ExitCodes.Warnings); }

            // ---- Stop and restore (before anything slow) -----------------------------------------
            _state.Phase = RunPhase.Stopping;
            _state.Save();
            if (!_signals.FastPath)
            {
                // Counters survive 'pktmon stop', but read them while the session is certainly there.
                var counters = await _s.Runner.RunAsync(PktmonCommand.Counters(dropReason: true)).ConfigureAwait(false);
                WriteText("counters.txt", counters.Output);
                var countersJson = await _s.Runner.RunAsync(PktmonCommand.Counters(json: true)).ConfigureAwait(false);
                if (countersJson.Success) WriteText("counters.json", countersJson.StdOut);
            }
            await EnsureMachineRestoredAsync().ConfigureAwait(false);

            if (_signals.FastPath)
            {
                Warn("Stopped in a hurry (console closing, or Ctrl+C twice): pktmon is stopped and the filters are back, but the .etl was not converted or zipped.");
                return await FinishAsync("Interrupted", ExitCodes.Warnings, skipZip: true).ConfigureAwait(false);
            }

            // ---- Convert -------------------------------------------------------------------
            if (!_o.NoPcap) await ConvertAsync().ConfigureAwait(false);
            return await FinishAsync("Finished", null).ConfigureAwait(false);
        }

        // ---- While recording -------------------------------------------------------------

        private async Task MonitorAsync(CancellationToken ct)
        {
            string applied = null;
            try { applied = NormalizeFilters((await _s.Filters.ReadAsync(log: false).ConfigureAwait(false)).Raw); } catch { }
            bool filtersWarned = false;
            var lastFilterCheck = DateTime.UtcNow;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
                    var r = await _s.Runner.RunAsync(PktmonCommand.Status(), log: false, ct: ct).ConfigureAwait(false);
                    if (r.ExitCode >= 0)
                    {
                        var st = StatusParser.Parse(r.Output);
                        if (!st.Running || (st.LogFile != null && !HeadlessPaths.IsUnder(st.LogFile, _runFolder)))
                        {
                            _signals.Trigger(StopReason.PktmonEndedExternally);
                            return;
                        }
                    }
                    var free = SystemChecks.FreeBytes(_runFolder);
                    if (free.HasValue && free.Value < LowDiskBytes)
                    {
                        _signals.Trigger(StopReason.LowDisk);
                        return;
                    }
                    if (!filtersWarned && applied != null && DateTime.UtcNow - lastFilterCheck > TimeSpan.FromSeconds(60))
                    {
                        lastFilterCheck = DateTime.UtcNow;
                        var now = await _s.Filters.ReadAsync(log: false).ConfigureAwait(false);
                        if (NormalizeFilters(now.Raw) != applied)
                        {
                            filtersWarned = true;
                            Warn($"The machine's filters changed during the capture (now {now.Count}, from {now.Owner}); pktmon applies them from that point on.");
                            AddCode(ExitCodes.Warnings);
                        }
                    }
                }
                catch (OperationCanceledException) { return; }
                catch { /* try again next round */ }
            }
        }

        private static string NormalizeFilters(string raw) =>
            string.Join("\n", (raw ?? "").Replace("\r", "").Split('\n').Select(l => l.TrimEnd()).Where(l => l.Length > 0));

        private static string Describe(StopReason reason, TimeSpan? duration)
        {
            switch (reason)
            {
                case StopReason.Duration: return $"after {DurationParser.Format(duration ?? TimeSpan.Zero)} (--duration)";
                case StopReason.StopRequested: return "on request (PktmonGUI.exe --stop)";
                case StopReason.CtrlC: return "by Ctrl+C";
                case StopReason.ConsoleClosed: return "because the console was closing";
                case StopReason.PktmonEndedExternally: return "because pktmon's session ended on its own, or someone ran 'pktmon stop'";
                case StopReason.LowDisk: return "because free disk space fell under 1 GB";
                default: return "for an unknown reason";
            }
        }

        // ---- Stop and restore --------------------------------------------------------------

        /// <summary>
        /// Stops pktmon if this run started it, then puts the machine's filters back. Safe to call
        /// more than once; every exit path goes through it.
        /// </summary>
        private async Task EnsureMachineRestoredAsync()
        {
            if (_s == null) { _signals?.MachineRestored.Set(); return; }
            if (_captureStarted && _s.Session.State != SessionState.Idle)
            {
                try
                {
                    var etl = await _s.Session.StopAsync("headless: stopped " + (_result?.StopReason ?? "")).ConfigureAwait(false);
                    if (etl != null) _etl = etl;
                }
                catch (Exception ex) { Error("Stopping pktmon failed: " + ex.Message); }

                var after = StatusParser.Parse((await _s.Runner.RunAsync(PktmonCommand.Status(), log: false).ConfigureAwait(false)).Output);
                if (after.Running && IsUnderRunFolder(after.LogFile))
                {
                    Error("pktmon is still recording after 'pktmon stop'. Run 'pktmon stop', then PktmonGUI.exe --cleanup.");
                    AddCode(ExitCodes.NotRestored);
                }
            }
            if (!_restoreDone && (_filtersTouched || _s.Snapshots.HasPendingRestore))
            {
                _restoreDone = true;
                var r = await _s.RestoreMachineFiltersAsync().ConfigureAwait(false);
                if (_result.Filters == null) _result.Filters = new RunResult.FiltersInfo();
                _result.Filters.Restored = r.Ok;
                _result.Filters.RestoreAction = r.Action;
                if (!r.Ok)
                {
                    _result.Filters.RestoreFailures = r.Failures;
                    Error("Some of the machine's filters couldn't be put back:\n" + string.Join("\n", r.Failures) +
                          (_s.Snapshots.Folder != null ? $"\nThe snapshot is in {_s.Snapshots.Folder}." : ""));
                    AddCode(ExitCodes.NotRestored);
                }
                else _log.Info("Machine filters: " + r.Action + ".");
                // The machine no longer holds our rules.
                _s.Settings.AppliedFilterListRaw = null;
                _s.Settings.AppliedRules = new List<FilterRule>();
                _s.Store.Save();
            }
            _signals?.MachineRestored.Set();
        }

        /// <summary>Crash handler: stop pktmon and restore the filters, at most 20 s, then record the crash.</summary>
        public void EmergencyStop(Exception ex)
        {
            if (Interlocked.Exchange(ref _emergency, 1) == 1) return;
            try
            {
                Error("PktmonGUI crashed: " + ex);
                Task.Run(EnsureMachineRestoredAsync).Wait(TimeSpan.FromSeconds(20));
            }
            catch { }
            try
            {
                if (_result != null)
                {
                    _result.Status = "Crashed";
                    _result.Stopped = DateTimeOffset.Now;
                    _result.ExitCode = ExitCodes.Worst(Codes().Concat(new[] { ExitCodes.Failed }));
                    _result.Meaning = ExitCodes.Describe(_result.ExitCode.Value);
                    SaveResult();
                }
                if (_state != null)
                {
                    _state.Phase = RunPhase.Failed;
                    _state.LastResult = _result;
                    _state.Save();
                }
            }
            catch { }
        }

        // ---- Convert -----------------------------------------------------------------------

        private async Task ConvertAsync()
        {
            _state.Phase = RunPhase.Finishing;
            _state.Save();
            var sidecar = _etl != null ? AttributionSnapshot.PathFor(_etl) : null;
            if (sidecar != null && !File.Exists(sidecar)) sidecar = null;
            var counts = _result.Counts ?? (_result.Counts = new RunResult.CountsInfo());
            counts.Attribution = _s.Session.Attribution?.Stats;
            if (counts.Attribution?.FlowsEvicted > 0)
                Warn($"{counts.Attribution.FlowsEvicted:N0} flows were dropped from the attribution table (over {FlowTable.MaxEntries:N0}); some packets may show no process.");

            var etls = Directory.GetFiles(_runFolder, "*.etl").OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
            if (etls.Count == 0) { Warn("pktmon wrote no .etl file."); AddCode(ExitCodes.Warnings); return; }
            foreach (var etl in etls)
            {
                var pcap = Path.ChangeExtension(etl, ".pcapng");
                _log.Info($"Converting {Path.GetFileName(etl)} to {Path.GetFileName(pcap)}" + (sidecar != null ? " with process comments" : ""));
                var c = await EtlConverter.ToPcapngAsync(_s.Runner, etl, pcap, sidecar).ConfigureAwait(false);
                if (!c.Success)
                {
                    Warn(c.Error + " The .etl is kept.");
                    AddCode(ExitCodes.Warnings);
                    continue;
                }
                counts.PacketsTotal = (counts.PacketsTotal ?? 0) + (c.Summary.PacketsTotal ?? 0);
                counts.Drops = (counts.Drops ?? 0) + (c.Summary.Drops ?? 0);
                if (c.Comments != null)
                {
                    if (counts.Comments == null) counts.Comments = c.Comments;
                    else
                    {
                        counts.Comments.Packets += c.Comments.Packets;
                        counts.Comments.Commented += c.Comments.Commented;
                        counts.Comments.WithProcess += c.Comments.WithProcess;
                        counts.Comments.NoProcess += c.Comments.NoProcess;
                        counts.Comments.Unknown += c.Comments.Unknown;
                        counts.Comments.Undecoded += c.Comments.Undecoded;
                    }
                    _log.Info("Process comments: " + c.Comments);
                }
                if (c.CommentError != null) { Warn("The pcapng was written, but its process comments couldn't be added: " + c.CommentError); AddCode(ExitCodes.Warnings); }
            }

            // The sidecar meta.json gets the packet count, as the GUI's Files page shows it.
            try
            {
                var metaPath = CaptureSession.MetaPathFor(_etl);
                var meta = Json.Load<CaptureMeta>(metaPath);
                if (meta != null && counts.PacketsTotal.HasValue) { meta.Packets = counts.PacketsTotal; Json.Save(metaPath, meta); }
            }
            catch { }
        }

        // ---- Finish: result, zip, collect ---------------------------------------------------

        private async Task<int> FinishAsync(string status, int? code, string error = null, bool skipZip = false)
        {
            if (error != null) Error(error);
            if (code.HasValue) AddCode(code.Value);
            try { await EnsureMachineRestoredAsync().ConfigureAwait(false); } catch (Exception ex) { Error("Restoring the machine failed: " + ex.Message); AddCode(ExitCodes.NotRestored); }

            _result.Status = status;
            if (_result.Stopped == null) _result.Stopped = DateTimeOffset.Now;
            SetExitCode();
            _result.Files = FileList();
            _state?.Let(s => { s.Phase = RunPhase.Finishing; s.Save(); });

            bool zipped = false;
            if (status == "Failed" && code == ExitCodes.Usage && !_o.KeepLocal) DiscardRunFolder();
            else if (!skipZip && Directory.Exists(_runFolder)) zipped = Zip();
            else _result.Zip = null;
            if (_o.Collect != null)
            {
                if (zipped) await CollectAsync().ConfigureAwait(false);
                else { Error($"Nothing was copied to {_o.Collect}: there's no zip."); AddCode(ExitCodes.CollectFailed); }
            }

            var final = SetExitCode();
            if (_o.KeepLocal && Directory.Exists(_runFolder)) SaveResult();
            if (_state != null)
            {
                _state.Phase = status == "Finished" || status == "Interrupted" || status == "Cancelled" ? RunPhase.Finished : RunPhase.Failed;
                _state.LastResult = _result;
                _state.Zip = _result.Zip;
                _state.Save();
            }
            PrintSummary();
            Current = null;
            return final;
        }

        private int SetExitCode()
        {
            var code = ExitCodes.Worst(Codes());
            _result.ExitCode = code;
            _result.Meaning = ExitCodes.Describe(code);
            return code;
        }

        private bool Zip()
        {
            string partial = null;
            try
            {
                var files = RunFolderFiles(_runFolder, out var links);
                foreach (var link in links) Warn($"Left {link} out of the zip: it's a link.");
                var free = FreeZipPath(_zip);
                if (free != _zip) { Warn($"Something was already at {_zip}, so the zip is {free}."); _zip = free; }
                _result.Zip = _zip;
                _log.Info("Zipping the results to " + _zip);
                SaveResult();
                // run.log is complete; from here the log continues in cli.log.
                _log.SwitchTo(HeadlessPaths.CliLog);
                _log.Detail($"--- {_runName}: zipping {_runFolder}");

                // A name nobody can guess, created new (never an existing file or link), for SYSTEM and Administrators only.
                var candidate = Path.Combine(Path.GetDirectoryName(_zip), $".{Path.GetFileName(_zip)}.{Guid.NewGuid():N}.partial");
                using (var stream = SecureFolder.CreateNewFile(candidate))
                {
                    partial = candidate; // ours from here: deleted if anything below fails
                    using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
                        foreach (var f in files)
                            zip.CreateEntryFromFile(f, _runName + "/" + f.Substring(_runFolder.TrimEnd('\\').Length + 1).Replace('\\', '/'), CompressionLevel.Optimal);
                }
                using (var z = ZipFile.OpenRead(partial))
                    if (z.Entries.Count != files.Count) throw new IOException("the zip doesn't hold every file");
                File.Move(partial, _zip); // fails rather than replace anything that appeared meanwhile
                partial = null;
                _result.ZipBytes = new FileInfo(_zip).Length;
                _result.ZipSha256 = Sha256(_zip);
                _state?.Let(s => { s.Zip = _zip; s.Save(); });
                if (!_o.KeepLocal)
                {
                    Directory.Delete(_runFolder, recursive: true);
                    _log.Detail("Removed the run folder; everything is in the zip.");
                }
                return true;
            }
            catch (Exception ex)
            {
                try { if (partial != null) File.Delete(partial); } catch { }
                Warn($"Couldn't zip the run folder ({ex.Message}); the files are in {_runFolder}.");
                AddCode(ExitCodes.Warnings);
                _result.Zip = null;
                return false;
            }
        }

        /// <summary>
        /// Every file in the run folder, walked by hand so a link is never followed; links are listed in
        /// <paramref name="links"/> and left out. (ZipFile.CreateFromDirectory follows them.)
        /// </summary>
        internal static List<string> RunFolderFiles(string runFolder, out List<string> links)
        {
            var files = new List<string>();
            links = new List<string>();
            var pending = new Stack<string>();
            pending.Push(runFolder);
            while (pending.Count > 0)
            {
                foreach (var entry in Directory.GetFileSystemEntries(pending.Pop()))
                {
                    var attrs = File.GetAttributes(entry);
                    if ((attrs & FileAttributes.ReparsePoint) != 0) links.Add(entry);
                    else if ((attrs & FileAttributes.Directory) != 0) pending.Push(entry);
                    else files.Add(entry);
                }
            }
            files.Sort(StringComparer.OrdinalIgnoreCase);
            return files;
        }

        /// <summary><paramref name="zip"/>, or "&lt;name&gt;-2.zip", "-3"… if something is already there (a link counts).</summary>
        internal static string FreeZipPath(string zip)
        {
            bool Taken(string p) { try { File.GetAttributes(p); return true; } catch (FileNotFoundException) { return false; } catch (DirectoryNotFoundException) { return false; } }
            var free = zip;
            for (int n = 2; Taken(free); n++)
                free = Path.Combine(Path.GetDirectoryName(zip), Path.GetFileNameWithoutExtension(zip) + "-" + n + ".zip");
            return free;
        }

        /// <summary>
        /// A usage error found after preflight (e.g. --comp matched nothing): nothing was recorded, so
        /// no zip is made and the run folder goes; the error stays in cli.log and the result.
        /// </summary>
        private void DiscardRunFolder()
        {
            _result.Zip = null;
            _log.SwitchTo(HeadlessPaths.CliLog);
            List<string> errors;
            lock (_gate) errors = _result.Errors.ToList();
            _log.Detail($"--- {_runName}: usage error ({string.Join(" ", errors)}); removing {_runFolder}");
            try
            {
                if (Directory.Exists(_runFolder)) Directory.Delete(_runFolder, recursive: true);
                _result.RunFolder = null;
                _result.Files = new List<string>();
            }
            catch (Exception ex) { _log.Detail($"Couldn't remove {_runFolder}: {ex.Message}"); }
        }

        private void ProbeCollect()
        {
            try
            {
                try { Directory.CreateDirectory(_o.Collect); } catch { }
                var probe = Path.Combine(_o.Collect, $".{HeadlessPaths.SanitizeHost(_host)}-probe-{Guid.NewGuid():N}");
                using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write)) { }
                File.Delete(probe);
            }
            catch (Exception ex)
            {
                Warn($"Can't write to {_o.Collect} right now ({ex.Message}).{CollectHint(ex)} The capture runs anyway; the zip is copied at the end if that works by then.");
            }
        }

        private async Task CollectAsync()
        {
            var name = Path.GetFileName(_zip);
            Exception last = null;
            foreach (var delay in new[] { 0, 5, 15, 30 })
            {
                if (delay > 0) await Task.Delay(TimeSpan.FromSeconds(delay)).ConfigureAwait(false);
                try
                {
                    try { Directory.CreateDirectory(_o.Collect); } catch { }
                    var dest = FreeZipPath(Path.Combine(_o.Collect, name));
                    CopyNew(_zip, Path.Combine(_o.Collect, $".{Path.GetFileName(dest)}.{Guid.NewGuid():N}.partial"), dest);
                    if (new FileInfo(dest).Length != new FileInfo(_zip).Length) throw new IOException("the copy's size doesn't match the zip");
                    _result.CollectedTo = dest;
                    _log.Info("Copied the zip to " + dest);
                    if (!_o.KeepLocal)
                    {
                        File.Delete(_zip);
                        _result.Zip = dest; // always a zip that exists
                        _log.Detail("Removed the local zip; the copy at " + dest + " is the result.");
                    }
                    return;
                }
                catch (Exception ex)
                {
                    last = ex;
                    _log.Warn($"Copying the zip to {_o.Collect} failed: {ex.Message}");
                }
            }
            Error($"Couldn't copy the zip to {_o.Collect}: {last?.Message}{CollectHint(last)} It's kept at {_zip}.");
            AddCode(ExitCodes.CollectFailed);
        }

        /// <summary>
        /// Copies <paramref name="source"/> to a new file at <paramref name="partial"/> (never an existing file
        /// or link), then renames it to <paramref name="dest"/>, which must not exist. Locally the copy is for
        /// SYSTEM and Administrators only; on a share it gets the share's own permissions.
        /// </summary>
        internal static void CopyNew(string source, string partial, string dest, System.Security.Principal.SecurityIdentifier alsoAllow = null)
        {
            bool share = partial.StartsWith(@"\\", StringComparison.Ordinal), created = false;
            try
            {
                using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16))
                using (var output = share ? new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16)
                                          : SecureFolder.CreateNewFile(partial, alsoAllow))
                {
                    created = true;
                    input.CopyTo(output);
                }
                File.Move(partial, dest); // fails rather than replace anything that appeared at dest meanwhile
            }
            catch
            {
                // Only a file this call created is removed: CreateNew failing means whatever is there isn't ours.
                if (created) try { File.Delete(partial); } catch { }
                throw;
            }
        }

        private static string CollectHint(Exception ex)
        {
            if (!(ex is UnauthorizedAccessException) && !(ex is IOException)) return "";
            if (SystemChecks.IsSystem())
                return $" Running as SYSTEM, the share sees this computer's account ({Environment.UserDomainName}\\{Environment.MachineName}$): give it write access to the share and the folder.";
            if (SystemChecks.IsNetworkLogon())
                return " This process runs on a network logon (WinRM, or PsExec without -s), which has no credentials to pass to another server (the \"double hop\"). Pull the zip instead, e.g. Copy-Item -FromSession, or run as SYSTEM.";
            return "";
        }

        // ---- Output ------------------------------------------------------------------------

        private void PrintSummary()
        {
            if (_o.Json)
            {
                if (!_o.DetachedChild) _console.WriteLine(HeadlessJson.ToAscii(_result));
                return;
            }
            var lines = new List<string> { $"{_result.Status}: exit {_result.ExitCode} ({_result.Meaning})" };
            if (_result.StopReason != null) lines.Add("  Stopped " + _result.StopReason);
            var c = _result.Counts;
            if (c?.PacketsTotal != null)
                lines.Add($"  Packets: {c.PacketsTotal:N0}" + (c.Drops > 0 ? $" ({c.Drops:N0} dropped)" : "") +
                          (c.Comments != null ? $"; {c.Comments.WithProcess:N0} with a process comment" : ""));
            if (_result.CollectedTo != null) lines.Add("  Copied to: " + _result.CollectedTo);
            if (_result.Zip != null && File.Exists(_result.Zip)) lines.Add($"  Zip: {_result.Zip} ({Bytes(_result.ZipBytes ?? 0)})");
            else if (Directory.Exists(_runFolder)) lines.Add("  Files: " + _runFolder);
            lock (_gate)
            {
                if (_result.Warnings.Count > 0) lines.Add($"  {_result.Warnings.Count} warning(s); see result.json");
            }
            _log.Final(string.Join(Environment.NewLine, lines));
        }

        private void SaveResult()
        {
            if (_result == null || _runFolder == null || !Directory.Exists(_runFolder)) return;
            try { lock (_gate) Json.Save(Path.Combine(_runFolder, "result.json"), _result); } catch { }
        }

        private void WriteText(string name, string text)
        {
            try { File.WriteAllText(Path.Combine(_runFolder, name), text ?? "", new System.Text.UTF8Encoding(false)); }
            catch (Exception ex) { _log.Warn($"Couldn't write {name}: {ex.Message}"); }
        }

        private List<string> FileList()
        {
            try
            {
                if (!Directory.Exists(_runFolder)) return _result.Files;
                return Directory.GetFiles(_runFolder).Select(f => $"{Path.GetFileName(f)} ({Bytes(new FileInfo(f).Length)})").OrderBy(s => s).ToList();
            }
            catch { return _result.Files; }
        }

        /// <summary>A capture that can't begin (not elevated, no pktmon, busy): report it the way a run would.</summary>
        public int RunEnvironmentFailure(string message, int code = ExitCodes.Unsupported) => EarlyExit(code, message);

        /// <summary>Exit before any run folder exists (no data folder, bad --out): say why, in cli.log too.</summary>
        private int EarlyExit(int code, string message)
        {
            var log = new RunLog(HeadlessPaths.CliLog, _o.LogFile, _console, Verbosity);
            log.Error(message);
            // The detached child's run folder is usually under runs\: never write there unless the data folder is safe,
            // nor under an --out that was refused.
            if (_o.RunFolder != null && !_outUnsafe &&
                !(HeadlessPaths.IsUnder(_o.RunFolder, HeadlessPaths.DataFolder) && HeadlessPaths.EnsureDataFolder() != null))
            {
                try
                {
                    if (CreateRunFolder(_o.RunFolder, out _) != null) return FinishEarlyExit(code, message);
                    Json.Save(Path.Combine(_o.RunFolder, "result.json"), new RunResult
                    {
                        Status = "Failed", ExitCode = code, Meaning = ExitCodes.Describe(code), Host = _host, Version = Version,
                        CommandLine = CommandLineText(_o.RawArgs), Started = DateTimeOffset.Now, Errors = { message },
                    });
                }
                catch { }
            }
            return FinishEarlyExit(code, message);
        }

        private int FinishEarlyExit(int code, string message)
        {
            if (_o.Json && !_o.DetachedChild)
                _console.WriteLine(HeadlessJson.ToAscii(new RunResult { Status = "Failed", ExitCode = code, Meaning = ExitCodes.Describe(code), Host = _host, Errors = { message } }));
            return code;
        }

        /// <summary>
        /// The run folder holds every packet: it's made for SYSTEM and Administrators only, whatever --out
        /// lets others do. One that's already there and isn't like that is set aside (see <see cref="SecureFolder"/>).
        /// </summary>
        private static string CreateRunFolder(string runFolder, out string setAside)
        {
            setAside = null;
            try
            {
                var parent = Path.GetDirectoryName(runFolder.TrimEnd('\\', '/'));
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent); // runs\, under the safe data folder
            }
            catch (Exception ex) { return $"Couldn't create {runFolder}: {ex.Message}"; }
            return SecureFolder.Ensure(runFolder, out setAside);
        }

        private void Warn(string text)
        {
            lock (_gate) _result?.Warnings.Add(text);
            _log?.Warn(text);
        }

        private void Error(string text)
        {
            lock (_gate) _result?.Errors.Add(text);
            _log?.Error(text);
        }

        private void AddCode(int code) { lock (_gate) _codes.Add(code); }
        private List<int> Codes() { lock (_gate) return _codes.ToList(); }

        // ---- Helpers -----------------------------------------------------------------------

        private bool IsUnderRunFolder(string path) => path != null && HeadlessPaths.IsUnder(path, _runFolder);

        /// <summary>A pktmon log file in a headless run folder: this tool started that session.</summary>
        private bool IsHeadlessLogFile(string path) =>
            path != null && (HeadlessPaths.IsUnder(path, HeadlessPaths.RunsFolder) || (_o.Out != null && HeadlessPaths.IsUnder(path, _o.Out)));

        /// <summary>
        /// Whether another PktmonGUI that may own PktmonGUI's ETW sessions is running: the GUI (started
        /// without arguments) or --dump-etw. Other headless processes don't count, such as the --detach
        /// launcher still waiting for its child, or --status; a running headless capture is found
        /// through headless.json instead.
        /// </summary>
        internal static bool OtherPktmonGuiRunning()
        {
            List<int> others;
            string exeName;
            try
            {
                using (var me = Process.GetCurrentProcess())
                {
                    exeName = me.ProcessName + ".exe";
                    others = Process.GetProcessesByName(me.ProcessName).Select(p => { using (p) return p.Id; }).Where(id => id != me.Id).ToList();
                }
            }
            catch { return false; }
            if (others.Count == 0) return false;

            try
            {
                var lines = new Dictionary<int, string>();
                var wql = "SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name = '" + exeName.Replace("\\", "\\\\").Replace("'", "\\'") + "'";
                using (var searcher = new System.Management.ManagementObjectSearcher(wql))
                using (var found = searcher.Get())
                    foreach (System.Management.ManagementBaseObject p in found)
                        using (p) lines[Convert.ToInt32(p["ProcessId"])] = p["CommandLine"] as string;
                return others.Any(id => !lines.TryGetValue(id, out var cmd) || MayOwnEtwSessions(cmd));
            }
            catch { return true; } // can't tell what they are: leave their sessions alone
        }

        /// <summary>A PktmonGUI started with this command line may run PktmonGUI's ETW sessions.</summary>
        internal static bool MayOwnEtwSessions(string commandLine)
        {
            if (commandLine == null) return true;
            var cmd = commandLine.TrimStart();
            string args;
            if (cmd.StartsWith("\"", StringComparison.Ordinal))
            {
                int end = cmd.IndexOf('"', 1);
                args = end < 0 ? "" : cmd.Substring(end + 1);
            }
            else
            {
                int space = cmd.IndexOfAny(new[] { ' ', '\t' });
                args = space < 0 ? "" : cmd.Substring(space + 1);
            }
            args = args.Trim();
            return args.Length == 0 || args.StartsWith("--dump-etw", StringComparison.OrdinalIgnoreCase);
        }

        internal static string CommandLineText(IEnumerable<string> args) =>
            "PktmonGUI.exe " + string.Join(" ", args.Select(PktmonCommand.QuoteArg));

        /// <summary>
        /// "1.2 GB". Not <c>Util.BytesConverter</c>: that's a WPF value converter, and touching it would
        /// load PresentationFramework into headless mode.
        /// </summary>
        internal static string Bytes(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            double v = bytes / 1024.0;
            string[] units = { "KB", "MB", "GB", "TB" };
            int u = 0;
            while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
            return v.ToString(v < 10 ? "0.0" : "0", System.Globalization.CultureInfo.InvariantCulture) + " " + units[u];
        }

        private static string Sha256(string path)
        {
            using (var sha = SHA256.Create())
            using (var f = File.OpenRead(path))
                return BitConverter.ToString(sha.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
        }
    }

    internal static class ObjectExtensions
    {
        public static void Let<T>(this T value, Action<T> action) where T : class
        {
            if (value != null) action(value);
        }
    }
}
