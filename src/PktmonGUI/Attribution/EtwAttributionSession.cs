using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace PktmonGUI.Attribution
{
    /// <summary>
    /// The real-time ETW session that runs beside pktmon: Microsoft-Windows-Kernel-Network for
    /// socket events (PID + 4-tuple), Microsoft-Windows-Kernel-Process for process starts and
    /// stops, and Microsoft-Windows-DNS-Client for the process each Dnscache query is for.
    /// A real-time session outlives a crashed process, so the name is fixed and a leftover is
    /// stopped at launch (<see cref="StopLeftover"/>).
    /// </summary>
    public sealed class EtwAttributionSession : IDisposable
    {
        public const string SessionName = "PktmonGUI-Attribution";
        public static readonly Guid KernelNetwork = new Guid("7DD42A49-5329-4832-8DFD-43D979153A88");
        public static readonly Guid KernelProcess = new Guid("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");
        public static readonly Guid DnsClient = new Guid("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
        /// <summary>The pktmon driver's own provider: Config 0x1, Rundown 0x2, NblParsed 0x4, NblInfo 0x8, Payload 0x10, CompRegister 0x20.</summary>
        public static readonly Guid PktMon = new Guid("4D4F80D9-C8BD-4D73-BB5B-19C90402C5AC");
        public const ulong NetworkKeywords = 0x30;   // KERNEL_NETWORK_KEYWORD_IPV4 | IPV6
        public const ulong ProcessKeywords = 0x10;   // WINEVENT_KEYWORD_PROCESS

        private TraceEventSession _session;
        private Thread _pump;
        private long _eventsSeen;

        /// <summary>Raised on the ETW thread.</summary>
        public event Action<FlowEvent> FlowEventReceived;
        /// <summary>pid, image path (a \Device\ path from the event; null if unreadable), parent pid, time.</summary>
        public event Action<int, string, int?, DateTime> ProcessStarted;
        /// <summary>pid, time, image base name.</summary>
        public event Action<int, DateTime, string> ProcessStopped;
        /// <summary>A query the DNS Client service sent, and the PID it was for. Raised on the ETW thread.</summary>
        public event Action<DnsQueryEvent> DnsQueryReceived;
        /// <summary>Every decoded event, for the --dump-etw fixture mode.</summary>
        public event Action<TraceEvent> RawEvent;

        public Func<IPAddress, bool> IsLocal { get; set; }
        public long EventsSeen => Interlocked.Read(ref _eventsSeen);
        public int EventsLost { get { try { return _session?.EventsLost ?? 0; } catch { return 0; } } }
        public bool IsRunning => _session != null;
        /// <summary>False when the DNS-Client provider couldn't be enabled; the rest works without it.</summary>
        public bool DnsClientEnabled { get; private set; }

        /// <summary>
        /// The equivalent logman command, for the "Commands run" panel. PktmonGUI starts the
        /// session itself; this is what it amounts to.
        /// </summary>
        public static string EquivalentCommand =>
            $"logman start {SessionName} -ets -rt -p Microsoft-Windows-Kernel-Network 0x30 -p Microsoft-Windows-Kernel-Process 0x10 -p Microsoft-Windows-DNS-Client 0xFFFFFFFFFFFFFFFF 0x4";

        public static bool LeftoverExists()
        {
            try { return TraceEventSession.GetActiveSessionNames().Contains(SessionName); }
            catch { return false; }
        }

        public static bool StopLeftover()
        {
            try
            {
                using (var s = TraceEventSession.GetActiveSession(SessionName))
                {
                    if (s == null) return false;
                    s.Stop();
                    return true;
                }
            }
            catch { return false; }
        }

        /// <param name="allNetworkEvents">Also enable TCP send/receive (the fixture dump wants every shape).</param>
        /// <param name="pktMonKeywords">Also enable Microsoft-Windows-PktMon with these keywords (0 = off).</param>
        public void Start(bool allNetworkEvents = false, ulong pktMonKeywords = 0)
        {
            if (_session != null) return;
            StopLeftover();

            var session = new TraceEventSession(SessionName, null) { StopOnDispose = true, BufferSizeMB = 16 };
            try
            {
                var netOptions = new TraceEventProviderOptions();
                if (!allNetworkEvents) netOptions.EventIDsToEnable = NetworkEventMapper.LiveEventIds.ToList();
                session.EnableProvider(KernelNetwork, TraceEventLevel.Informational, NetworkKeywords, netOptions);
                session.EnableProvider(KernelProcess, TraceEventLevel.Informational, ProcessKeywords,
                    new TraceEventProviderOptions { EventIDsToEnable = new List<int> { 1, 2 } });
                // Only "query sent to DNS server", once per query Dnscache sends.
                try
                {
                    session.EnableProvider(DnsClient, TraceEventLevel.Informational, ulong.MaxValue,
                        new TraceEventProviderOptions { EventIDsToEnable = new List<int> { DnsQueryEvent.EventId } });
                    DnsClientEnabled = true;
                }
                catch { DnsClientEnabled = false; }
                if (pktMonKeywords != 0)
                    session.EnableProvider(PktMon, TraceEventLevel.Informational, pktMonKeywords);

                // Registered (manifest) providers are decoded through TDH by RegisteredTraceEventParser.
                var parser = new RegisteredTraceEventParser(session.Source);
                parser.All += OnEvent;
                session.Source.UnhandledEvents += OnEvent;
            }
            catch
            {
                session.Dispose();
                throw;
            }
            _session = session;
            _pump = new Thread(() =>
            {
                try { session.Source.Process(); }
                catch { /* session stopped */ }
            })
            { IsBackground = true, Name = "ETW attribution" };
            _pump.Start();
        }

        private void OnEvent(TraceEvent e)
        {
            Interlocked.Increment(ref _eventsSeen);
            try
            {
                RawEvent?.Invoke(e);
                int id = (int)e.ID;
                if (e.ProviderGuid == KernelNetwork)
                {
                    var fe = NetworkEventMapper.Map(id, name => Payload(e, name), e.TimeStamp, IsLocal);
                    if (fe != null) FlowEventReceived?.Invoke(fe);
                }
                else if (e.ProviderGuid == DnsClient)
                {
                    var q = DnsQueryEvent.Map(id, name => Payload(e, name), e.TimeStamp);
                    if (q != null) DnsQueryReceived?.Invoke(q);
                }
                else if (e.ProviderGuid == KernelProcess)
                {
                    int? pid = NetworkEventMapper.ToInt(Payload(e, "ProcessID"));
                    if (pid == null) return;
                    if (id == 1)
                        ProcessStarted?.Invoke(pid.Value,
                            Payload(e, "ImageName") as string ?? ProcessEventMapper.StartImageName(e.EventData(), e.Version),
                            NetworkEventMapper.ToInt(Payload(e, "ParentProcessID")), e.TimeStamp);
                    else if (id == 2)
                        ProcessStopped?.Invoke(pid.Value, e.TimeStamp, Payload(e, "ImageName") as string);
                }
            }
            catch { /* one malformed event must not stop the session */ }
        }

        private static object Payload(TraceEvent e, string name)
        {
            int i = Array.FindIndex(e.PayloadNames, n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
            return i < 0 ? null : e.PayloadValue(i);
        }

        public void Dispose()
        {
            var s = _session;
            _session = null;
            if (s == null) return;
            try { s.Source.StopProcessing(); } catch { }
            try { s.Dispose(); } catch { }
            _pump?.Join(2000);
        }
    }
}
