using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace PktmonGUI.Attribution
{
    /// <summary>
    /// Microsoft-Windows-DNS-Client event 3010, "DNS Query sent to DNS Server". Programs that resolve
    /// names through Windows (getaddrinfo, DnsQueryEx) don't send DNS themselves: the DNS Client
    /// service (Dnscache, in svchost) does, from its own sockets. It logs this event as it sends,
    /// with the PID of the process the query is for (ClientPID, template version 1).
    /// </summary>
    public sealed class DnsQueryEvent
    {
        public const int EventId = 3010;

        /// <summary>Lower case, no trailing dot.</summary>
        public string Name { get; set; }
        public int Type { get; set; }
        /// <summary>Null when the event's server field isn't an address.</summary>
        public IPAddress Server { get; set; }
        /// <summary>Null on builds whose event 3010 has no ClientPID (template version 0).</summary>
        public int? ClientPid { get; set; }
        public DateTime Time { get; set; }

        /// <summary>Fields are read by name (QueryName, QueryType, DnsServerIpAddress, ClientPID).</summary>
        public static DnsQueryEvent Map(int id, Func<string, object> field, DateTime time)
        {
            if (id != EventId) return null;
            var name = DnsQuestion.NormalizeName(field("QueryName") as string);
            var type = NetworkEventMapper.ToInt(field("QueryType"));
            if (name == null || type == null) return null;
            IPAddress.TryParse((field("DnsServerIpAddress") as string)?.Trim() ?? "", out var server);
            return new DnsQueryEvent
            {
                Name = name,
                Type = type.Value,
                Server = NetEndpoint.Normalize(server),
                ClientPid = NetworkEventMapper.ToInt(field("ClientPID")),
                Time = time,
            };
        }
    }

    /// <summary>A DNS message's ID and first question, from pktmon's text or from the frame's bytes.</summary>
    public sealed class DnsQuestion
    {
        public int Id { get; set; }
        public bool IsResponse { get; set; }
        /// <summary>Lower case, no trailing dot. Null for a response read from text: pktmon prints only its answers.</summary>
        public string Name { get; set; }
        /// <summary>Null when the type's name isn't known here.</summary>
        public int? Type { get; set; }

        // "30259+ A? example.com. (29)", "47182+ [1au] A? app-gw.contoso.local. (58)"
        private static readonly Regex QueryRx = new Regex(@"^(?<id>\d{1,5})[+*\-$|]*\s+(?:\[\d+au\]\s+)?(?<type>[A-Za-z0-9]+)\?\s+(?<name>\S+)", RegexOptions.Compiled);
        // "30259 2/0/0 A 172.66.147.243 (61)", "2 NXDomain 0/1/0 (108)"
        private static readonly Regex IdRx = new Regex(@"^(?<id>\d{1,5})[+*\-$|]*\s", RegexOptions.Compiled);

        private static readonly Dictionary<string, int> Types = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["A"] = 1, ["NS"] = 2, ["CNAME"] = 5, ["SOA"] = 6, ["PTR"] = 12, ["MX"] = 15, ["TXT"] = 16, ["AAAA"] = 28,
            ["SRV"] = 33, ["NAPTR"] = 35, ["DS"] = 43, ["RRSIG"] = 46, ["DNSKEY"] = 48, ["SVCB"] = 64, ["HTTPS"] = 65, ["ANY"] = 255,
        };

        /// <summary>From pktmon's DNS text (the part after the addresses), or null if it isn't DNS.</summary>
        public static DnsQuestion FromText(string info)
        {
            if (string.IsNullOrEmpty(info)) return null;
            var q = QueryRx.Match(info);
            if (q.Success)
                return new DnsQuestion
                {
                    Id = int.Parse(q.Groups["id"].Value, CultureInfo.InvariantCulture),
                    Name = NormalizeName(q.Groups["name"].Value),
                    Type = TypeNumber(q.Groups["type"].Value),
                };
            var r = IdRx.Match(info);
            return r.Success ? new DnsQuestion { Id = int.Parse(r.Groups["id"].Value, CultureInfo.InvariantCulture), IsResponse = true } : null;
        }

        /// <summary>From a DNS message starting at <paramref name="o"/> (the UDP payload), or null if it's too short.</summary>
        public static DnsQuestion FromBytes(byte[] b, int o)
        {
            if (b.Length < o + 12) return null;
            var q = new DnsQuestion { Id = b[o] << 8 | b[o + 1], IsResponse = (b[o + 2] & 0x80) != 0 };
            if ((b[o + 4] << 8 | b[o + 5]) == 0) return q;
            var name = new StringBuilder();
            int at = o + 12;
            while (true)
            {
                if (at >= b.Length || name.Length > 255) return q;
                int len = b[at++];
                if (len == 0) break;
                // A compression pointer can't occur in the first question; a longer label means it isn't DNS.
                if (len > 63 || at + len > b.Length) return q;
                if (name.Length > 0) name.Append('.');
                name.Append(Encoding.ASCII.GetString(b, at, len));
                at += len;
            }
            if (at + 2 > b.Length) return q;
            q.Name = NormalizeName(name.ToString());
            q.Type = b[at] << 8 | b[at + 1];
            return q;
        }

        internal static int? TypeNumber(string s)
        {
            if (Types.TryGetValue(s, out var n)) return n;
            // Types without a name are printed as "Type65".
            if (s.StartsWith("Type", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(s.Substring(4), NumberStyles.None, CultureInfo.InvariantCulture, out n)) return n;
            return null;
        }

        internal static string NormalizeName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return null;
            name = name.Trim().TrimEnd('.').ToLowerInvariant();
            return name.Length == 0 ? null : name;
        }
    }

    /// <summary>
    /// The queries Dnscache sent (event 3010), to find which process a DNS packet was for. A packet
    /// matches the latest event for its name, type and server at or before its time: Dnscache logs the
    /// event just before it sends. Dnscache reuses its sockets for different names, so this is decided
    /// per packet, never per flow. Responses are printed without their question, so each query seen
    /// on the wire is remembered by flow and DNS ID for its response to find.
    /// </summary>
    public sealed class DnsRequesterTable
    {
        /// <summary>How long before a packet its event may be: Dnscache resends unanswered queries for several seconds.</summary>
        public static readonly TimeSpan Before = TimeSpan.FromSeconds(10);
        /// <summary>Timestamp skew between pktmon's packets and ETW events.</summary>
        public static readonly TimeSpan After = TimeSpan.FromSeconds(1);
        private static readonly TimeSpan KeepQueries = TimeSpan.FromMinutes(2);
        public const int MaxEvents = 100_000;

        private readonly Dictionary<string, List<DnsQueryEvent>> _sent = new Dictionary<string, List<DnsQueryEvent>>(StringComparer.Ordinal);
        private readonly Dictionary<string, (DnsQuestion question, DateTime time)> _queries = new Dictionary<string, (DnsQuestion, DateTime)>(StringComparer.Ordinal);
        private int _count;

        public int Count => _count;
        public IEnumerable<DnsQueryEvent> Sent => _sent.Values.SelectMany(l => l);

        public void Add(DnsQueryEvent e)
        {
            if (!_sent.TryGetValue(e.Name, out var list)) _sent[e.Name] = list = new List<DnsQueryEvent>(2);
            list.Add(e);
            _count++;
        }

        /// <summary>The event for this query; a null type or server matches any.</summary>
        public DnsQueryEvent Find(string name, int? type, IPAddress server, DateTime time)
        {
            if (name == null || !_sent.TryGetValue(name, out var list)) return null;
            DnsQueryEvent before = null, after = null;
            foreach (var e in list)
            {
                if (type != null && e.Type != type.Value) continue;
                if (server != null && e.Server != null && !e.Server.Equals(server)) continue;
                if (e.Time <= time)
                {
                    if (time - e.Time <= Before && (before == null || e.Time > before.Time)) before = e;
                }
                else if (e.Time - time <= After && (after == null || e.Time < after.Time)) after = e;
            }
            return before ?? after;
        }

        public void NoteQuery(string flowKey, DnsQuestion q, DateTime time) =>
            _queries[flowKey + "#" + q.Id.ToString(CultureInfo.InvariantCulture)] = (q, time);

        public bool TryGetQuery(string flowKey, int id, out DnsQuestion q, out DateTime time)
        {
            var found = _queries.TryGetValue(flowKey + "#" + id.ToString(CultureInfo.InvariantCulture), out var v);
            q = v.question;
            time = v.time;
            return found;
        }

        /// <summary>Forgets queries whose response is long past; if there are too many events, the oldest go.</summary>
        public void Evict(DateTime now)
        {
            foreach (var key in _queries.Where(kv => now - kv.Value.time > KeepQueries).Select(kv => kv.Key).ToList())
                _queries.Remove(key);
            if (_count <= MaxEvents) return;
            var cutoff = Sent.Select(e => e.Time).OrderBy(t => t).ElementAt(_count - MaxEvents);
            foreach (var key in _sent.Keys.ToList())
            {
                var list = _sent[key];
                _count -= list.RemoveAll(e => e.Time < cutoff);
                if (list.Count == 0) _sent.Remove(key);
            }
        }
    }
}
