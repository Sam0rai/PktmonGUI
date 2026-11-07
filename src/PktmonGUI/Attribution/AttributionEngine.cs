using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using PktmonGUI.Model;

namespace PktmonGUI.Attribution
{
    public sealed class AttributionStats
    {
        public long Packets { get; set; }
        public long Resolved { get; set; }
        public long NoProcess { get; set; }
        public long Unknown { get; set; }
        public long Pending { get; set; }
        public long EtwEvents { get; set; }
        public int EtwLost { get; set; }
        public string EtwError { get; set; }
        /// <summary>Flows dropped because the flow table hit its size cap; their packets may show no process.</summary>
        public long FlowsEvicted { get; set; }

        /// <summary>Share of packets that should have a process (so excluding ARP, ICMP, ...) that got one.</summary>
        public double? AttributedShare
        {
            get
            {
                long owned = Resolved + Unknown;
                return owned == 0 ? (double?)null : (double)Resolved / owned;
            }
        }
    }

    /// <summary>
    /// Joins pktmon's packets to the processes that own their sockets. Kernel-Network events and
    /// the connection tables build a flow table (5-tuple → PID over time); each packet is looked up
    /// by its tuple at the time pktmon logged it. Packets that arrive before their event (a SYN
    /// is logged a few ms before the connect event) are held as Pending and backfilled.
    /// DNS that the DNS Client service sends for other processes also gets the process that
    /// asked, from DNS-Client events (<see cref="DnsRequesterTable"/>).
    /// </summary>
    public sealed class AttributionEngine : IDisposable
    {
        public static readonly TimeSpan PendingTimeout = TimeSpan.FromSeconds(3);
        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

        private readonly object _lock = new object();
        private readonly IClock _clock;
        private readonly FlowTable _flows = new FlowTable();
        private readonly ProcessRegistry _processes = new ProcessRegistry();
        private readonly DnsRequesterTable _dns = new DnsRequesterTable();
        private readonly HashSet<IPAddress> _local = new HashSet<IPAddress>();
        private readonly Dictionary<long, ProcessAttribution> _groups = new Dictionary<long, ProcessAttribution>();
        private readonly List<(PacketRecord packet, DateTime deadline)> _pending = new List<(PacketRecord, DateTime)>();
        private readonly bool _offline;
        /// <summary>False when no DNS-Client events can come, so Dnscache's packets don't wait for one.</summary>
        private bool _dnsEventsExpected = true;
        private EtwAttributionSession _etw;
        private Timer _poll;
        private DateTime _lastPoll;
        private int _pollTicks;
        private long _packets, _resolved, _noProcess, _unknown;

        public AttributionEngine(IClock clock = null, bool offline = false)
        {
            _clock = clock ?? SystemClock.Instance;
            _offline = offline;
        }

        public DateTime Started { get; private set; }
        public DateTime? Stopped { get; private set; }
        public bool IsRunning => _poll != null;
        public string EtwError { get; private set; }

        /// <summary>
        /// Keep closed flows for the whole capture instead of 5 minutes. Record mode sets it: its sidecar
        /// is matched against every packet of the .etl after the capture stops. Set before <see cref="Start"/>.
        /// </summary>
        public bool RetainClosedFlows { get; set; }

        public AttributionStats Stats
        {
            get
            {
                lock (_lock)
                    return new AttributionStats
                    {
                        Packets = _packets, Resolved = _resolved, NoProcess = _noProcess, Unknown = _unknown, Pending = _pending.Count,
                        EtwEvents = _etw?.EventsSeen ?? 0, EtwLost = _etw?.EventsLost ?? 0, EtwError = EtwError,
                        FlowsEvicted = _flows.EvictedByCap,
                    };
            }
        }

        // ---- Lifecycle ----------------------------------------------------------------

        /// <summary>
        /// Starts the ETW session first, then seeds from the connection tables and running
        /// processes, so nothing opened in between is missed. If ETW can't start (e.g. the
        /// system's 64-session limit), attribution carries on from the 2 s table polls alone.
        /// </summary>
        public void Start(bool useEtw = true)
        {
            Started = _clock.Now;
            if (useEtw)
            {
                try
                {
                    var etw = new EtwAttributionSession { IsLocal = IsLocal };
                    etw.FlowEventReceived += Apply;
                    etw.ProcessStarted += (pid, path, parent, t) =>
                    {
                        // The event carries the path; if its payload couldn't be read, ask the process (if it's still alive).
                        var p = path ?? SystemSeeder.ImagePath(pid);
                        lock (_lock) _processes.Started(pid, p, parent, t);
                    };
                    etw.ProcessStopped += (pid, t, name) => { lock (_lock) _processes.Stopped(pid, t, name); };
                    etw.DnsQueryReceived += ApplyDns;
                    etw.Start();
                    _etw = etw;
                }
                catch (Exception ex)
                {
                    EtwError = ex.Message;
                }
            }
            _dnsEventsExpected = _etw != null && _etw.DnsClientEnabled;

            var now = _clock.Now;
            var services = SafeServices();
            lock (_lock)
            {
                foreach (var ip in SystemSeeder.LocalAddresses()) _local.Add(ip);
                _processes.Seed(SystemSeeder.Processes(), services);
            }
            SeedConnections(SystemSeeder.Connections(), FlowTable.Beginning, now);
            _lastPoll = now;
            _poll = new Timer(_ => Poll(), null, PollInterval, PollInterval);
        }

        public void Stop()
        {
            Stopped = _clock.Now;
            _poll?.Dispose();
            _poll = null;
            _etw?.Dispose();
            lock (_lock)
            {
                // Whatever is still pending gets one last chance, then is final.
                foreach (var (p, _) in _pending) Finish(p, final: true);
                _pending.Clear();
            }
        }

        public void Dispose() => Stop();

        private static Dictionary<int, List<string>> SafeServices()
        {
            try { return SystemSeeder.ServicesByPid(); } catch { return new Dictionary<int, List<string>>(); }
        }

        private void Poll()
        {
            try
            {
                var now = _clock.Now;
                // A flow first seen in this poll started after the previous one.
                SeedConnections(SystemSeeder.Connections(), _lastPoll, now);
                _lastPoll = now;
                if (++_pollTicks % 15 == 0)
                {
                    var services = SafeServices();
                    lock (_lock)
                    {
                        _processes.UpdateServices(services);
                        _flows.Evict(now, keepClosed: RetainClosedFlows);
                        _dns.Evict(now);
                        if (_groups.Count > 200_000) _groups.Clear();
                    }
                }
                if (_etw == null)
                {
                    // No ETW: pick up new processes from snapshots instead of Kernel-Process events.
                    var procs = SystemSeeder.Processes();
                    lock (_lock)
                        foreach (var p in procs.Where(p => !_processes.HasLive(p.Pid)))
                            _processes.Seed(new[] { p }, services: null);
                }
            }
            catch { /* the next poll tries again */ }
        }

        internal void SeedConnections(IEnumerable<TableConnection> table, DateTime from, DateTime now)
        {
            lock (_lock)
            {
                foreach (var c in table)
                {
                    if (c.Pid == 0) continue; // TIME_WAIT: the owner has already closed it
                    if (c.Proto == FlowProto.Tcp && c.Remote.HasValue)
                        _flows.Open(FlowProto.Tcp, c.Local, c.Remote.Value, c.Pid, from, "connection table");
                    else
                        _flows.Bind(c.Proto, c.Local, c.Pid, from, c.Proto == FlowProto.Tcp ? "listening socket" : "UDP socket");
                }
            }
        }

        /// <summary>One Kernel-Network event (public for tests and the offline path).</summary>
        public void Apply(FlowEvent e)
        {
            lock (_lock)
            {
                if (!e.Local.IsUnspecified) _local.Add(e.Local.Ip);
                switch (e.Kind)
                {
                    case FlowEventKind.Connect:
                    case FlowEventKind.Reconnect:
                        _flows.Open(e.Proto, e.Local, e.Remote, e.Pid, e.Time, "TCP connect event");
                        break;
                    case FlowEventKind.Accept:
                        _flows.Open(e.Proto, e.Local, e.Remote, e.Pid, e.Time, "TCP accept event");
                        break;
                    case FlowEventKind.Fail:
                        // The SYNs of a failed attempt still belong to whoever tried.
                        _flows.Open(e.Proto, e.Local, e.Remote, e.Pid, e.Time, "TCP connect event (failed)");
                        _flows.Close(e.Proto, e.Local, e.Remote, e.Time);
                        break;
                    case FlowEventKind.Disconnect:
                        _flows.Close(e.Proto, e.Local, e.Remote, e.Time);
                        break;
                    case FlowEventKind.Send:
                    case FlowEventKind.Receive:
                        var src = e.Proto == FlowProto.Udp ? "UDP send/receive event" : "TCP data event";
                        _flows.Open(e.Proto, e.Local, e.Remote, e.Pid, e.Time, src);
                        if (e.Proto == FlowProto.Udp) _flows.Bind(FlowProto.Udp, e.Local, e.Pid, e.Time, src);
                        break;
                }
            }
        }

        /// <summary>One DNS-Client event 3010 (public for tests and the offline path).</summary>
        public void ApplyDns(DnsQueryEvent e)
        {
            lock (_lock)
            {
                // This build's event has no ClientPID: nothing to match, so stop waiting for it.
                if (e.ClientPid == null) _dnsEventsExpected = false;
                else _dns.Add(e);
            }
        }

        internal void SeedProcesses(IEnumerable<ProcessSnapshotEntry> procs, IDictionary<int, List<string>> services)
        {
            lock (_lock) _processes.Seed(procs, services);
        }

        internal void ProcessStarted(int pid, string path, int? parent, DateTime t) { lock (_lock) _processes.Started(pid, path, parent, t); }
        internal void ProcessStopped(int pid, DateTime t, string name) { lock (_lock) _processes.Stopped(pid, t, name); }
        internal void AddLocal(IPAddress ip) { lock (_lock) _local.Add(NetEndpoint.Normalize(ip)); }

        public bool IsLocal(IPAddress ip)
        {
            if (ip == null) return false;
            if (IPAddress.IsLoopback(ip)) return true;
            lock (_lock) return _local.Contains(ip);
        }

        // ---- Packets ------------------------------------------------------------------

        /// <summary>Attributes one packet (called on pktmon's output thread, or offline for loaded captures).</summary>
        public ProcessAttribution Observe(PacketRecord p)
        {
            lock (_lock)
            {
                _packets++;
                var a = Resolve(p, final: _offline);
                p.Attribution = a;
                if (a.State == AttributionState.Pending) _pending.Add((p, _clock.Now + PendingTimeout));
                else Count(a, +1);
                return a;
            }
        }

        /// <summary>Retries pending packets; returns those whose attribution changed. Call on the UI thread.</summary>
        public List<PacketRecord> TakeBackfilled()
        {
            var changed = new List<PacketRecord>();
            lock (_lock)
            {
                if (_pending.Count == 0) return changed;
                var now = _clock.Now;
                for (int i = _pending.Count - 1; i >= 0; i--)
                {
                    var (p, deadline) = _pending[i];
                    if (Finish(p, final: now >= deadline))
                    {
                        _pending.RemoveAt(i);
                        changed.Add(p);
                    }
                }
            }
            return changed;
        }

        /// <summary>Re-resolves a pending packet; true when it's now final.</summary>
        private bool Finish(PacketRecord p, bool final)
        {
            var a = Resolve(p, final);
            if (a.State == AttributionState.Pending) return false;
            p.Attribution = a;
            Count(a, +1);
            return true;
        }

        private void Count(ProcessAttribution a, int d)
        {
            switch (a.State)
            {
                case AttributionState.Resolved:
                case AttributionState.System: _resolved += d; break;
                case AttributionState.NoProcess: _noProcess += d; break;
                case AttributionState.Unknown: _unknown += d; break;
            }
        }

        private ProcessAttribution Resolve(PacketRecord p, bool final)
        {
            // 1. Not IP: nothing above the link layer owns it.
            if (p.SrcIp == null || p.DstIp == null)
                return ProcessAttribution.None(LinkLayerReason(p));

            // 2. ICMP & co. are answered by the TCP/IP stack itself.
            bool tcp = p.IpProtocol == 6, udp = p.IpProtocol == 17;
            if (!tcp && !udp)
                return ProcessAttribution.None(p.IpProtocol == 1 || p.IpProtocol == 58
                    ? "ICMP is handled by the TCP/IP stack"
                    : $"{p.Protocol} has no socket owner");

            // 3. Same packet already attributed at another component.
            if (p.PktGroupId.HasValue && _groups.TryGetValue(p.PktGroupId.Value, out var grouped))
                return grouped;

            if (!NetEndpoint.TryCreate(p.SrcIp, p.SrcPort, out var src) || !NetEndpoint.TryCreate(p.DstIp, p.DstPort, out var dst))
                return final ? ProcessAttribution.NotFound("no ports (IP fragment?)") : ProcessAttribution.Pending();

            // Learn this machine's addresses from what it sends.
            if (p.Direction == Direction.Tx && !IsGroupAddress(src.Ip)) _local.Add(src.Ip);
            bool srcLocal = IsLocalLocked(src.Ip), dstLocal = IsLocalLocked(dst.Ip);
            bool group = IsGroupAddress(dst.Ip);

            // 4. Neither end is this machine: routed, bridged or VM traffic.
            if (!srcLocal && !dstLocal && !group)
                return Remember(p, ProcessAttribution.None("neither address is on this machine (forwarded or VM traffic)"));

            var proto = tcp ? FlowProto.Tcp : FlowProto.Udp;
            var t = p.Time ?? _clock.Now;

            // A response is printed without its question: remember each query for its response to find.
            var dns = udp && (src.Port == 53) != (dst.Port == 53) ? Question(p) : null;
            if (dns != null && !dns.IsResponse && dns.Name != null) _dns.NoteQuery(FlowTable.FlowKey(proto, src, dst), dns, t);

            // 5. The exact flow.
            var entry = _flows.Find(proto, src, dst, t);
            if (entry == null)
            {
                // 6. A socket bound to the local port: unconnected UDP, or a TCP listener for inbound SYNs.
                var local = p.Direction == Direction.Tx && srcLocal ? src
                          : dstLocal || group ? dst
                          : src;
                entry = _flows.FindBinding(proto, local, t);
            }
            if (entry != null)
            {
                var found = Describe(entry, t, src, dst);
                // DNS the DNS Client service sent or received: also name the process it was for.
                if (dns != null && HostsDnscache(found) && !AddRequester(found, dns, src, dst, t))
                {
                    if (!final && _dnsEventsExpected) return ProcessAttribution.Pending();
                    if (_dnsEventsExpected && found.RequesterPid == null)
                        found.RequesterNote = "not found: no DNS-Client event for this name, type and server";
                }
                return Remember(p, found);
            }

            // 7. Broadcast/multicast nobody listens to.
            if (group)
                return Remember(p, ProcessAttribution.None("broadcast/multicast with no listening socket"));

            return final ? Remember(p, ProcessAttribution.NotFound(_etw == null && !_offline ? "ETW isn't running; only the connection table was used" : null))
                         : ProcessAttribution.Pending();
        }

        private static DnsQuestion Question(PacketRecord p) => p.Dns ?? (p.Dns = DnsQuestion.FromText(p.Info));

        private static bool HostsDnscache(ProcessAttribution a) =>
            a.Services != null && a.Services.IndexOf("Dnscache", StringComparison.OrdinalIgnoreCase) >= 0;

        /// <summary>
        /// Sets the process a Dnscache DNS packet was for, from the event 3010 Dnscache logged when it
        /// sent the query. False when the question is known but no event matches yet, or the process
        /// it names has no name yet: a short-lived requester like curl can exit before it could be
        /// asked, and only its stop event, a moment later, names it.
        /// </summary>
        private bool AddRequester(ProcessAttribution a, DnsQuestion q, NetEndpoint src, NetEndpoint dst, DateTime t)
        {
            var asked = q;
            var askedAt = t;
            // A response read from text has no question: take it from the query with the same ID on this flow.
            if (q.Name == null && !_dns.TryGetQuery(FlowTable.FlowKey(FlowProto.Udp, src, dst), q.Id, out asked, out askedAt))
                return true; // its query was before the capture: nothing to match on
            var sent = _dns.Find(asked.Name, asked.Type, q.IsResponse ? src.Ip : dst.Ip, askedAt);
            if (sent == null) return false;
            // A query Dnscache makes for itself names its own PID.
            if (sent.ClientPid is int pid && pid != 0 && pid != a.Pid)
            {
                var inst = _processes.Lookup(pid, t);
                a.RequesterPid = pid;
                a.RequesterName = inst?.Name;
                a.RequesterPath = inst?.Path;
                return inst?.Name != null;
            }
            return true;
        }

        private bool IsLocalLocked(IPAddress ip) => IPAddress.IsLoopback(ip) || _local.Contains(ip);

        private ProcessAttribution Remember(PacketRecord p, ProcessAttribution a)
        {
            if (p.PktGroupId.HasValue) _groups[p.PktGroupId.Value] = a;
            return a;
        }

        private ProcessAttribution Describe(FlowTable.Entry e, DateTime t, NetEndpoint a, NetEndpoint b)
        {
            if (e.Pid == 4)
                return new ProcessAttribution { State = AttributionState.System, Pid = 4, Name = "System", Source = e.Source, Reason = KernelHint(a.Port, b.Port) };
            var inst = _processes.Lookup(e.Pid, t);
            return new ProcessAttribution
            {
                State = AttributionState.Resolved,
                Pid = e.Pid,
                Name = inst?.Name, // null: the PID is known but the process exited before we could name it
                Path = inst?.Path,
                Services = inst != null && inst.Services.Count > 0 ? string.Join(", ", inst.Services) : null,
                Source = e.Source,
            };
        }

        /// <summary>Kernel-mode servers attribute to PID 4; say which one it probably is.</summary>
        internal static string KernelHint(int p1, int p2)
        {
            bool P(int n) => p1 == n || p2 == n;
            if (P(445) || P(139)) return "SMB (kernel)";
            if (P(80) || P(443)) return "HTTP.sys (kernel)";
            if (P(5985) || P(5986)) return "WinRM via HTTP.sys";
            if (P(3343)) return "cluster heartbeat";
            if (P(2049)) return "NFS (kernel)";
            if (P(3389)) return "RDP (kernel)";
            return "kernel";
        }

        private static string LinkLayerReason(PacketRecord p)
        {
            switch (p.Protocol)
            {
                case "ARP": return "ARP is answered by the TCP/IP stack";
                case "LLDP": case "CDP": case "STP": return $"{p.Protocol} is a link-layer switch protocol";
                case "EAPOL": return "802.1X authentication (link layer)";
                default: return "not IP traffic";
            }
        }

        private static bool IsGroupAddress(IPAddress ip)
        {
            if (ip == null) return false;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6) return ip.IsIPv6Multicast;
            var b = ip.GetAddressBytes();
            return b[0] >= 224 && b[0] <= 239 || b[3] == 255 || ip.Equals(IPAddress.Broadcast);
        }

        // ---- Record-mode sidecar ----------------------------------------------------------

        public AttributionSnapshot Export()
        {
            lock (_lock)
                return new AttributionSnapshot
                {
                    Started = Started,
                    Stopped = Stopped ?? _clock.Now,
                    EtwError = EtwError,
                    LocalAddresses = _local.Select(a => a.ToString()).ToList(),
                    DnsQueries = _dns.Sent.Select(AttributionSnapshot.DnsQueryRow.Of).ToList(),
                    Flows = _flows.Flows.Select(kv => AttributionSnapshot.FlowRow.Of(kv.Key, kv.Value)).ToList(),
                    Bindings = _flows.Bindings.Select(kv => AttributionSnapshot.FlowRow.Of(kv.Key, kv.Value)).ToList(),
                    Processes = _processes.All.Select(i => new AttributionSnapshot.ProcessRow
                    {
                        Pid = i.Pid, Name = i.Name, Path = i.Path, ParentPid = i.ParentPid, Start = i.Start, End = i.End,
                        Services = i.Services.Count == 0 ? null : i.Services,
                    }).ToList(),
                };
        }

        /// <summary>An engine for loaded captures: resolves from a sidecar, never pending.</summary>
        public static AttributionEngine FromSnapshot(AttributionSnapshot s)
        {
            var e = new AttributionEngine(offline: true) { Started = s.Started, Stopped = s.Stopped, EtwError = s.EtwError };
            foreach (var ip in s.LocalAddresses ?? new List<string>())
                if (IPAddress.TryParse(ip, out var a)) e._local.Add(NetEndpoint.Normalize(a));
            foreach (var f in s.Flows ?? new List<AttributionSnapshot.FlowRow>()) e._flows.AddRaw(false, f.Key, f.ToEntry());
            foreach (var f in s.Bindings ?? new List<AttributionSnapshot.FlowRow>()) e._flows.AddRaw(true, f.Key, f.ToEntry());
            // Sidecars from before DNS requesters were recorded have none; don't call their DNS "not found".
            e._dnsEventsExpected = s.DnsQueries != null;
            foreach (var d in s.DnsQueries ?? new List<AttributionSnapshot.DnsQueryRow>()) e._dns.Add(d.ToEvent());
            foreach (var p in s.Processes ?? new List<AttributionSnapshot.ProcessRow>())
                e._processes.Add(new ProcessRegistry.Instance
                {
                    Pid = p.Pid, Name = p.Name, Path = p.Path, ParentPid = p.ParentPid, Start = p.Start, End = p.End,
                    Services = p.Services ?? new List<string>(),
                });
            return e;
        }
    }

    /// <summary><c>&lt;capture&gt;.attribution.json</c>, written next to a Record-mode .etl.</summary>
    public sealed class AttributionSnapshot
    {
        public DateTime Started { get; set; }
        public DateTime Stopped { get; set; }
        public string EtwError { get; set; }
        public List<string> LocalAddresses { get; set; } = new List<string>();
        public List<FlowRow> Flows { get; set; } = new List<FlowRow>();
        public List<FlowRow> Bindings { get; set; } = new List<FlowRow>();
        public List<ProcessRow> Processes { get; set; } = new List<ProcessRow>();
        /// <summary>DNS-Client event 3010s: which process each Dnscache query was for. Null in older sidecars.</summary>
        public List<DnsQueryRow> DnsQueries { get; set; }

        public sealed class FlowRow
        {
            public string Key { get; set; }
            public int Pid { get; set; }
            public DateTime From { get; set; }
            public DateTime? To { get; set; }
            public string Source { get; set; }

            internal static FlowRow Of(string key, FlowTable.Entry e) =>
                new FlowRow { Key = key, Pid = e.Pid, From = e.From, To = e.To, Source = e.Source };

            internal FlowTable.Entry ToEntry() => new FlowTable.Entry { Pid = Pid, From = From, To = To, LastSeen = To ?? From, Source = Source };
        }

        public sealed class ProcessRow
        {
            public int Pid { get; set; }
            public string Name { get; set; }
            public string Path { get; set; }
            public int? ParentPid { get; set; }
            public DateTime Start { get; set; }
            public DateTime? End { get; set; }
            public List<string> Services { get; set; }
        }

        public sealed class DnsQueryRow
        {
            public DateTime Time { get; set; }
            public string Name { get; set; }
            public int Type { get; set; }
            public string Server { get; set; }
            public int ClientPid { get; set; }

            internal static DnsQueryRow Of(DnsQueryEvent e) =>
                new DnsQueryRow { Time = e.Time, Name = e.Name, Type = e.Type, Server = e.Server?.ToString(), ClientPid = e.ClientPid ?? 0 };

            internal DnsQueryEvent ToEvent() => new DnsQueryEvent
            {
                Time = Time, Name = Name, Type = Type, ClientPid = ClientPid,
                Server = IPAddress.TryParse(Server ?? "", out var ip) ? NetEndpoint.Normalize(ip) : null,
            };
        }

        public static string PathFor(string etl) => System.IO.Path.ChangeExtension(etl, null) + ".attribution.json";
    }
}
