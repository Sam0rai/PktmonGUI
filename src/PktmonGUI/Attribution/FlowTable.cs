using System;
using System.Collections.Generic;
using System.Linq;

namespace PktmonGUI.Attribution
{
    /// <summary>
    /// 5-tuple → owning PID over time. A tuple belongs to one socket at a time, but tuples
    /// are reused after TIME_WAIT, so each key holds a list of time-windowed entries.
    /// Keys are direction-free (the two endpoints are sorted), so a packet in either
    /// direction finds the same flow.
    /// </summary>
    public sealed class FlowTable
    {
        /// <summary>Packets may arrive before their connect/accept event (a SYN is logged before the socket reports it).</summary>
        public static readonly TimeSpan BeforeGrace = TimeSpan.FromSeconds(2);
        /// <summary>FIN/ACK tails and retransmits arrive after the disconnect event.</summary>
        public static readonly TimeSpan AfterGrace = TimeSpan.FromSeconds(30);
        public static readonly TimeSpan KeepClosed = TimeSpan.FromMinutes(5);
        public const int MaxEntries = 200_000;

        /// <summary>"Since before the capture": seeded entries cover any earlier packet time.</summary>
        public static readonly DateTime Beginning = new DateTime(2000, 1, 1);

        public sealed class Entry
        {
            public int Pid { get; set; }
            public DateTime From { get; set; }
            public DateTime? To { get; set; }
            public DateTime LastSeen { get; set; }
            public string Source { get; set; }

            internal bool Covers(DateTime t) => t >= From - BeforeGrace && (To == null || t <= To.Value + AfterGrace);
        }

        private readonly Dictionary<string, List<Entry>> _flows = new Dictionary<string, List<Entry>>();
        private readonly Dictionary<string, List<Entry>> _udpBindings = new Dictionary<string, List<Entry>>();
        private int _count;

        public int Count => _count;

        public static string FlowKey(FlowProto proto, NetEndpoint a, NetEndpoint b)
        {
            string ka = a.Key, kb = b.Key;
            return string.CompareOrdinal(ka, kb) <= 0
                ? (proto == FlowProto.Tcp ? "T|" : "U|") + ka + "|" + kb
                : (proto == FlowProto.Tcp ? "T|" : "U|") + kb + "|" + ka;
        }

        private static string BindingKey(FlowProto proto, NetEndpoint local) =>
            (proto == FlowProto.Tcp ? "T|" : "U|") + (local.IsUnspecified ? "*#" + local.Port : local.Key);
        private static string AnyBindingKey(FlowProto proto, int port) => (proto == FlowProto.Tcp ? "T|*#" : "U|*#") + port;

        // ---- Updates ------------------------------------------------------------------

        /// <summary>Records that <paramref name="pid"/> owns the flow from <paramref name="time"/> on.</summary>
        public void Open(FlowProto proto, NetEndpoint a, NetEndpoint b, int pid, DateTime time, string source) =>
            Upsert(_flows, FlowKey(proto, a, b), pid, time, source);

        public void Close(FlowProto proto, NetEndpoint a, NetEndpoint b, DateTime time)
        {
            if (!_flows.TryGetValue(FlowKey(proto, a, b), out var list)) return;
            foreach (var e in list.Where(e => e.To == null)) e.To = time;
        }

        /// <summary>
        /// A socket bound to a local port: an unconnected UDP socket (any remote peer on this port is
        /// its traffic), or a listening TCP socket (inbound SYNs before, or without, an accept).
        /// </summary>
        public void Bind(FlowProto proto, NetEndpoint local, int pid, DateTime time, string source) =>
            Upsert(_udpBindings, BindingKey(proto, local), pid, time, source);

        public void Unbind(FlowProto proto, NetEndpoint local, DateTime time)
        {
            if (!_udpBindings.TryGetValue(BindingKey(proto, local), out var list)) return;
            foreach (var e in list.Where(e => e.To == null)) e.To = time;
        }

        private void Upsert(Dictionary<string, List<Entry>> map, string key, int pid, DateTime time, string source)
        {
            if (!map.TryGetValue(key, out var list)) map[key] = list = new List<Entry>(1);
            var open = list.LastOrDefault(e => e.To == null);
            if (open != null && open.Pid == pid)
            {
                if (time > open.LastSeen) open.LastSeen = time;
                if (time < open.From) open.From = time;
                return;
            }
            // A different owner: the tuple was reused. Close the old socket where the new one starts.
            if (open != null) open.To = time;
            list.Add(new Entry { Pid = pid, From = time, LastSeen = time, Source = source });
            _count++;
        }

        // ---- Lookups ------------------------------------------------------------------

        public Entry Find(FlowProto proto, NetEndpoint a, NetEndpoint b, DateTime time) =>
            _flows.TryGetValue(FlowKey(proto, a, b), out var list) ? Best(list, time) : null;

        /// <summary>The socket bound to this local port: specific address first, then any address.</summary>
        public Entry FindBinding(FlowProto proto, NetEndpoint local, DateTime time)
        {
            if (_udpBindings.TryGetValue(BindingKey(proto, local), out var list))
            {
                var e = Best(list, time);
                if (e != null) return e;
            }
            return _udpBindings.TryGetValue(AnyBindingKey(proto, local.Port), out var any) ? Best(any, time) : null;
        }

        private static Entry Best(List<Entry> list, DateTime time)
        {
            Entry best = null;
            foreach (var e in list)
                if (e.Covers(time) && (best == null || e.From > best.From)) best = e;
            return best;
        }

        /// <summary>Entries dropped because the table outgrew <see cref="MaxEntries"/>; their packets may lose their process.</summary>
        public long EvictedByCap { get; private set; }

        /// <summary>
        /// Drops entries closed long ago; if still too large, the least recently seen go first.
        /// </summary>
        /// <param name="keepClosed">
        /// Keep closed entries however old (only the size cap applies). A Record capture's sidecar is
        /// matched against the whole .etl after it stops, so it needs every flow the capture saw.
        /// </param>
        public void Evict(DateTime now, bool keepClosed = false)
        {
            if (!keepClosed)
            {
                foreach (var map in new[] { _flows, _udpBindings })
                {
                    foreach (var key in map.Keys.ToList())
                    {
                        var list = map[key];
                        _count -= list.RemoveAll(e => e.To != null && now - e.To.Value > KeepClosed);
                        if (list.Count == 0) map.Remove(key);
                    }
                }
            }
            if (_count <= MaxEntries) return;
            var oldest = _flows.SelectMany(kv => kv.Value.Select(e => (kv.Key, e))).OrderBy(x => x.e.LastSeen).Take(_count - MaxEntries).ToList();
            foreach (var (key, e) in oldest)
            {
                _flows[key].Remove(e);
                if (_flows[key].Count == 0) _flows.Remove(key);
                _count--;
                EvictedByCap++;
            }
        }

        // ---- Export (Record-mode sidecar) ------------------------------------------------

        public IEnumerable<KeyValuePair<string, Entry>> Flows => _flows.SelectMany(kv => kv.Value.Select(e => new KeyValuePair<string, Entry>(kv.Key, e)));
        public IEnumerable<KeyValuePair<string, Entry>> Bindings => _udpBindings.SelectMany(kv => kv.Value.Select(e => new KeyValuePair<string, Entry>(kv.Key, e)));

        internal void AddRaw(bool binding, string key, Entry e)
        {
            var map = binding ? _udpBindings : _flows;
            if (!map.TryGetValue(key, out var list)) map[key] = list = new List<Entry>(1);
            list.Add(e);
            _count++;
        }
    }
}
