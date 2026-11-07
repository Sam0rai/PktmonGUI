using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PktmonGUI.Attribution;
using PktmonGUI.Model;
using PktmonGUI.Parsing;
using PktmonGUI.Pcap;
using PktmonGUI.Pktmon;
using PktmonGUI.Util;

namespace PktmonGUI.Services
{
    public enum SessionState { Idle, Starting, Running, Stopping, External }

    /// <summary>
    /// Owns the single pktmon session. pktmon allows one at a time per machine, so this is
    /// the only place that runs <c>pktmon start</c> / <c>pktmon stop</c>.
    /// </summary>
    public sealed class CaptureSession
    {
        private readonly PktmonRunner _runner;
        private readonly CommandLog _log;
        private readonly Stopwatch _elapsed = new Stopwatch();
        private StreamingProcess _stream;
        private RealtimeParser _parser;
        private readonly object _parserLock = new object();

        public CaptureSession(PktmonRunner runner, CommandLog log)
        {
            _runner = runner;
            _log = log;
        }

        public SessionState State { get; private set; }
        public CaptureOptions Options { get; private set; }
        public CaptureMeta Meta { get; private set; }
        public string MetaPath { get; private set; }
        public TimeSpan Elapsed => _elapsed.Elapsed;
        public bool IsActive => State == SessionState.Running || State == SessionState.Starting || State == SessionState.External;

        /// <summary>Parsed packets waiting for the UI to pick them up (Live mode).</summary>
        public ConcurrentQueue<PacketRecord> Incoming { get; } = new ConcurrentQueue<PacketRecord>();

        /// <summary>Non-packet lines pktmon printed (banners, errors) during a live session.</summary>
        public ConcurrentQueue<string> InfoLines { get; } = new ConcurrentQueue<string>();

        /// <summary>Events from extra ETW providers (--trace -p), waiting for the UI.</summary>
        public ConcurrentQueue<EtwEventRecord> IncomingEvents { get; } = new ConcurrentQueue<EtwEventRecord>();

        public event EventHandler StateChanged;
        /// <summary>Raised when the real-time process ended without us asking (error, external stop).</summary>
        public event EventHandler<string> UnexpectedExit;

        private void SetState(SessionState s)
        {
            State = s;
            UpdateKeepAwake();
            StateChanged?.Invoke(this, EventArgs.Empty);
        }

        // Held from start until the capture's files are written; not for a session someone else started.
        private readonly object _awakeLock = new object();
        private KeepAwake _awake;
        private bool _awakeWarned;

        private void UpdateKeepAwake()
        {
            string error = null;
            lock (_awakeLock)
            {
                bool want = State == SessionState.Starting || State == SessionState.Running || State == SessionState.Stopping;
                if (want && _awake == null)
                {
                    _awake = KeepAwake.Start("PktmonGUI is recording a packet capture", out var e);
                    if (_awake == null && !_awakeWarned) { _awakeWarned = true; error = e; }
                }
                else if (!want && _awake != null)
                {
                    _awake.Dispose();
                    _awake = null;
                }
            }
            if (error != null) _log.Note($"Couldn't keep Windows awake during the capture ({error}); it stops if the machine goes to sleep.");
        }

        /// <summary>A session started by someone else (or a crashed PktmonGUI) is running.</summary>
        public void MarkExternal()
        {
            if (State == SessionState.Idle) SetState(SessionState.External);
        }

        /// <summary>
        /// Process attribution for the running capture (null when off, or in counters-only mode).
        /// Kept after stop so the UI can still read its final stats.
        /// </summary>
        public AttributionEngine Attribution { get; private set; }

        /// <param name="saveLivePcap">Live mode: also save the packets (real bytes, via the PktMon ETW provider) as a pcapng.</param>
        public async Task StartAsync(CaptureOptions options, IReadOnlyList<Component> components, IReadOnlyList<FilterRule> filters,
                                     bool attributeProcesses = false, bool saveLivePcap = false, long livePcapMaxBytes = 2L << 30)
        {
            if (IsActive) throw new InvalidOperationException("A capture is already running.");
            var err = options.Validate().FirstOrDefault();
            if (err != null) throw new InvalidOperationException(err);

            Options = options.Clone();
            SetState(SessionState.Starting);
            try
            {
                while (Incoming.TryDequeue(out _)) { }
                while (InfoLines.TryDequeue(out _)) { }
                while (IncomingEvents.TryDequeue(out _)) { }

                if (options.Mode == CaptureMode.Record)
                    WriteMeta(options, components, filters);

                // Attribution starts first: its ETW session and connection-table seed must be in
                // place before pktmon's first packet arrives.
                Attribution = null;
                if (attributeProcesses && options.Mode != CaptureMode.CountersOnly)
                {
                    // Record mode matches the sidecar to the whole .etl after stop, so no flow may age out.
                    var engine = new AttributionEngine { RetainClosedFlows = options.Mode == CaptureMode.Record };
                    await Task.Run(() => engine.Start()).ConfigureAwait(false);
                    Attribution = engine;
                    _log.Note(engine.EtwError == null
                        ? "Process attribution: " + EtwAttributionSession.EquivalentCommand
                        : "Process attribution without ETW (" + engine.EtwError + "); using the connection table only");
                }

                // The packet tap too must be listening before pktmon's first packet.
                LastLivePcap = null;
                if (saveLivePcap && options.Mode == CaptureMode.Live)
                    StartLivePcap(options, components, filters, livePcapMaxBytes);

                var cmd = PktmonCommand.Start(options,
                    options.Mode == CaptureMode.CountersOnly ? "-o keeps it to counters only" :
                    "cwd " + _runner.WorkingDirectory);

                if (options.Mode == CaptureMode.Live)
                {
                    lock (_parserLock) _parser = new RealtimeParser();
                    _stream = _runner.StartStreaming(cmd, OnLiveLine);
                    var stream = _stream;
                    _ = stream.Exited.ContinueWith(t => OnStreamExited(stream, t.Result), TaskScheduler.Default);

                    // pktmon rejects bad arguments immediately; give it a moment to fail loudly.
                    var early = await Task.WhenAny(stream.Exited, Task.Delay(700)).ConfigureAwait(false);
                    if (early == stream.Exited)
                    {
                        var output = stream.Errors;
                        _stream = null;
                        throw new InvalidOperationException("pktmon exited right away: " +
                            (string.IsNullOrWhiteSpace(output) ? DrainInfo() : output.Trim()));
                    }
                }
                else
                {
                    var r = await _runner.RunAsync(cmd).ConfigureAwait(false);
                    if (!r.Success) throw r.ToException();
                }

                _elapsed.Restart();
                SetState(SessionState.Running);
            }
            catch
            {
                Attribution?.Stop();
                var tap = _tap;
                _tap = null;
                if (tap != null)
                {
                    try { tap.Stop(); File.Delete(tap.Path); if (MetaPath != null) File.Delete(MetaPath); } catch { }
                }
                SetState(SessionState.Idle);
                throw;
            }
        }

        private string DrainInfo()
        {
            var lines = new List<string>();
            while (InfoLines.TryDequeue(out var l)) lines.Add(l);
            return string.Join(Environment.NewLine, lines).Trim();
        }

        private void OnLiveLine(string line)
        {
            lock (_parserLock)
            {
                if (_parser == null) return;
                foreach (var p in _parser.Feed(line)) Emit(p);
                // An extra provider's event is its own thing: it is neither a packet nor the
                // banner/error text the Info queue drives, which it used to be mistaken for.
                if (_parser.LastLineKind == RealtimeParser.LineKind.Event)
                    IncomingEvents.Enqueue(_parser.LastEvent);
                else if (_parser.LastLineKind == RealtimeParser.LineKind.Info)
                    InfoLines.Enqueue(line);
            }
        }

        /// <summary>Attributes a packet (on this, pktmon's output thread) and hands it to the UI.</summary>
        private void Emit(PacketRecord p)
        {
            if (Attribution != null)
            {
                // Real-time timestamps carry no date; one logged just before midnight isn't tomorrow.
                if (p.Time.HasValue && p.Time.Value > DateTime.Now.AddHours(1)) p.Time = p.Time.Value.AddDays(-1);
                Attribution.Observe(p);
            }
            Incoming.Enqueue(p);
        }

        private void OnStreamExited(StreamingProcess stream, int code)
        {
            lock (_parserLock)
            {
                if (_parser != null)
                    foreach (var p in _parser.Flush()) Emit(p);
            }
            if (!ReferenceEquals(stream, _stream)) return;
            if (State == SessionState.Running)
            {
                // Nobody pressed Stop: pktmon died, or another admin ran 'pktmon stop'.
                _elapsed.Stop();
                _stream = null;
                Attribution?.Stop();
                if (_tap != null) FinishLivePcapAsync("pktmon ended on its own").Wait();
                SetState(SessionState.Idle);
                UnexpectedExit?.Invoke(this, $"pktmon ended on its own (exit {code}). {stream.Errors.Trim()}".Trim());
            }
        }

        // ---- Live capture → pcapng ------------------------------------------------------

        private PktMonPacketTap _tap;

        /// <summary>The pcapng written by the last Live capture (null if none).</summary>
        public LivePcapResult LastLivePcap { get; private set; }

        public sealed class LivePcapResult
        {
            public string Path { get; set; }
            public long Packets { get; set; }
            public long Skipped { get; set; }
            public long OverCap { get; set; }
            public int EventsLost { get; set; }
            public Pcap.CommentResult Comments { get; set; }
            public string Error { get; set; }

            public string Summary
            {
                get
                {
                    var s = $"{System.IO.Path.GetFileName(Path)} · {Packets:N0} packets";
                    if (Comments != null) s += $" · {Comments.WithProcess:N0} with a process comment";
                    if (OverCap > 0) s += $" · {OverCap:N0} left out after the size cap";
                    if (Skipped > 0) s += $" · {Skipped:N0} non-Ethernet packets not saved";
                    if (EventsLost > 0) s += $" · {EventsLost:N0} ETW events lost";
                    if (Error != null) s += " · " + Error;
                    return s;
                }
            }
        }

        private void StartLivePcap(CaptureOptions o, IReadOnlyList<Component> components, IReadOnlyList<FilterRule> filters, long maxBytes)
        {
            var path = Path.Combine(_runner.WorkingDirectory, $"live-{DateTime.Now:yyyyMMdd-HHmmss}.pcapng");
            WriteMeta(o, components, filters, path, "real-time (pcapng from the PktMon ETW provider)");
            try
            {
                var tap = new PktMonPacketTap(path, id => components.FirstOrDefault(c => c.Id == id)?.Name, maxBytes);
                tap.Start();
                _tap = tap;
                _log.Note("Saving packets to " + Path.GetFileName(path) + ": " + PktMonPacketTap.EquivalentCommand);
            }
            catch (Exception ex)
            {
                _log.Note("Couldn't save this Live capture as pcapng: " + ex.Message);
                Meta = null;
                try { File.Delete(path); File.Delete(MetaPath); } catch { }
            }
        }

        /// <summary>Closes the pcapng and, when processes were attributed, saves them beside it and comments every packet.</summary>
        private async Task FinishLivePcapAsync(string how)
        {
            var tap = _tap;
            _tap = null;
            if (tap == null) return;
            var result = new LivePcapResult { Path = tap.Path };
            try
            {
                await Task.Run(() => tap.Stop()).ConfigureAwait(false);
                result.Packets = tap.Packets;
                result.Skipped = tap.Skipped;
                result.OverCap = tap.OverCap;
                result.EventsLost = tap.EventsLost;
                if (Attribution != null && tap.Packets > 0)
                {
                    var snapshot = Attribution.Export();
                    var sidecar = AttributionSnapshot.PathFor(tap.Path);
                    Json.Save(sidecar, snapshot);
                    result.Comments = await Task.Run(() => Pcap.ProcessCommenter.Annotate(tap.Path, tap.Path, snapshot, Path.GetFileName(sidecar))).ConfigureAwait(false);
                    if (Meta != null) Meta.AttributionFile = Path.GetFileName(sidecar);
                }
            }
            catch (Exception ex) { result.Error = ex.Message; }
            if (Meta != null)
            {
                Meta.Stopped = DateTime.Now;
                Meta.StoppedHow = how;
                Meta.Packets = result.Packets;
                SaveMeta();
            }
            LastLivePcap = result;
            _log.Note("Saved " + result.Summary);
        }

        /// <summary>
        /// Stops the session with <c>pktmon stop</c> (rather than Ctrl+C, which a GUI can't send cleanly).
        /// Returns the .etl path in Record mode.
        /// </summary>
        public async Task<string> StopAsync(string how = "cleanly, by this tool")
        {
            if (State == SessionState.Idle) return null;
            var mode = Options?.Mode;
            bool external = State == SessionState.External;
            SetState(SessionState.Stopping);
            try
            {
                await _runner.RunAsync(PktmonCommand.Stop(external ? "session was already running before PktmonGUI" : null)).ConfigureAwait(false);

                var stream = _stream;
                _stream = null;
                if (stream != null)
                {
                    var done = await Task.WhenAny(stream.Exited, Task.Delay(5000)).ConfigureAwait(false);
                    if (done != stream.Exited) stream.Kill();
                    lock (_parserLock)
                    {
                        if (_parser != null) foreach (var p in _parser.Flush()) Emit(p);
                        _parser = null;
                    }
                }
                _elapsed.Stop();
                Attribution?.Stop();

                if (mode == CaptureMode.Live && _tap != null)
                {
                    await FinishLivePcapAsync(how).ConfigureAwait(false);
                    return null;
                }

                if (mode == CaptureMode.Record && Meta != null)
                {
                    Meta.Stopped = DateTime.Now;
                    Meta.StoppedHow = how;
                    if (Attribution != null)
                    {
                        // The .etl has no process data; the flow table recorded alongside it does.
                        var sidecar = AttributionSnapshot.PathFor(Meta.EtlFile);
                        try
                        {
                            Json.Save(sidecar, Attribution.Export());
                            Meta.AttributionFile = Path.GetFileName(sidecar);
                        }
                        catch (Exception ex) { _log.Note("Couldn't save process attribution: " + ex.Message); }
                    }
                    SaveMeta();
                    return Meta.EtlFile;
                }
                return null;
            }
            finally
            {
                SetState(SessionState.Idle);
            }
        }

        // ---- Record-mode metadata -------------------------------------------------

        private void WriteMeta(CaptureOptions o, IReadOnlyList<Component> components, IReadOnlyList<FilterRule> filters,
                               string captureFile = null, string logMode = null)
        {
            var etl = captureFile ?? (Path.IsPathRooted(o.FileName) ? o.FileName : Path.Combine(_runner.WorkingDirectory, o.FileName));
            Meta = new CaptureMeta
            {
                EtlFile = etl,
                Started = DateTime.Now,
                ComponentIds = o.AllNics ? new List<int>() : o.ComponentIds.ToList(),
                ComponentNames = o.AllNics ? new List<string> { "all NICs" }
                    : o.ComponentIds.Select(id => components.FirstOrDefault(c => c.Id == id)?.Name ?? ("id " + id)).ToList(),
                Wireless = components.Where(c => o.ComponentIds.Contains(c.Id)).Any(c => c.IsWireless),
                Filters = filters.ToList(),
                PacketSize = o.PacketSize,
                LogMode = logMode ?? CaptureOptions.LogModeArg(o.LogMode),
                FileSizeMb = captureFile != null ? null : o.FileSizeMb,
                CommandLine = PktmonCommand.Start(o).DisplayText,
                StoppedHow = "still running, or ended without PktmonGUI",
            };
            MetaPath = MetaPathFor(etl);
            SaveMeta();
        }

        private void SaveMeta()
        {
            try { Json.Save(MetaPath, Meta); } catch { }
        }

        public static string MetaPathFor(string etl) => Path.ChangeExtension(etl, null) + ".meta.json";

        /// <summary>
        /// Best-effort synchronous stop for app shutdown and crash handlers, where awaiting isn't possible.
        /// </summary>
        public void StopBlocking(TimeSpan timeout)
        {
            if (State == SessionState.Idle || State == SessionState.External) return;
            try
            {
                var t = StopAsync("PktmonGUI closed");
                t.Wait(timeout);
            }
            catch { }
            _stream?.Kill();
        }
    }
}
