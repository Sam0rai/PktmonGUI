using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;

namespace PktmonGUI.Attribution
{
    /// <summary>
    /// Microsoft-Windows-Kernel-Network event → <see cref="FlowEvent"/>. Event IDs come from the
    /// provider manifest (TCPv4 10–18, TCPv6 26–34, UDPv4 42/43, UDPv6 58/59); fields are read by
    /// name (PID, saddr, daddr, sport, dport), so this works on decoded payloads from TraceEvent
    /// and on the JSON fixture alike.
    /// </summary>
    public static class NetworkEventMapper
    {
        private static readonly Dictionary<int, (FlowProto proto, FlowEventKind kind)> Ids = new Dictionary<int, (FlowProto, FlowEventKind)>
        {
            [10] = (FlowProto.Tcp, FlowEventKind.Send), [11] = (FlowProto.Tcp, FlowEventKind.Receive),
            [12] = (FlowProto.Tcp, FlowEventKind.Connect), [13] = (FlowProto.Tcp, FlowEventKind.Disconnect),
            [15] = (FlowProto.Tcp, FlowEventKind.Accept), [16] = (FlowProto.Tcp, FlowEventKind.Reconnect),
            [17] = (FlowProto.Tcp, FlowEventKind.Fail),
            [26] = (FlowProto.Tcp, FlowEventKind.Send), [27] = (FlowProto.Tcp, FlowEventKind.Receive),
            [28] = (FlowProto.Tcp, FlowEventKind.Connect), [29] = (FlowProto.Tcp, FlowEventKind.Disconnect),
            [31] = (FlowProto.Tcp, FlowEventKind.Accept), [32] = (FlowProto.Tcp, FlowEventKind.Reconnect),
            [42] = (FlowProto.Udp, FlowEventKind.Send), [43] = (FlowProto.Udp, FlowEventKind.Receive),
            [58] = (FlowProto.Udp, FlowEventKind.Send), [59] = (FlowProto.Udp, FlowEventKind.Receive),
        };

        /// <summary>
        /// The event IDs the live session enables: connection lifecycle for TCP (data events would
        /// cost one event per send/receive and add nothing the connection table can't) and send/receive
        /// for UDP, which has no connection events.
        /// </summary>
        public static readonly int[] LiveEventIds = { 12, 13, 15, 16, 17, 28, 29, 31, 32, 42, 43, 58, 59 };

        /// <summary>
        /// The fields hold ports in network byte order. Set from the captured fixture (see
        /// tests Fixtures/etw); if TraceEvent already swapped them this becomes false.
        /// </summary>
        public static bool PortsAreNetworkOrder { get; set; } = true;

        public static bool IsKnown(int id) => Ids.ContainsKey(id);

        /// <summary>
        /// Builds a flow event, or null when the ID isn't a flow event or a field is missing.
        /// <paramref name="isLocal"/> decides which of saddr/daddr is this machine; when neither or
        /// both are (loopback), saddr is taken as local.
        /// </summary>
        public static FlowEvent Map(int id, Func<string, object> field, DateTime time, Func<IPAddress, bool> isLocal = null)
        {
            if (!Ids.TryGetValue(id, out var kind)) return null;
            var pid = ToInt(field("PID"));
            var s = ToAddress(field("saddr"));
            var d = ToAddress(field("daddr"));
            var sp = ToPort(field("sport"));
            var dp = ToPort(field("dport"));
            if (pid == null || s == null || d == null || sp == null || dp == null) return null;

            var src = new NetEndpoint(s, sp.Value);
            var dst = new NetEndpoint(d, dp.Value);
            bool swap = isLocal != null && !isLocal(src.Ip) && isLocal(dst.Ip);
            return new FlowEvent
            {
                Proto = kind.proto,
                Kind = kind.kind,
                Pid = pid.Value,
                Local = swap ? dst : src,
                Remote = swap ? src : dst,
                Time = time,
            };
        }

        internal static int? ToInt(object v)
        {
            switch (v)
            {
                case null: return null;
                case int i: return i;
                case uint u: return unchecked((int)u);
                case long l: return (int)l;
                case ulong ul: return (int)ul;
                case ushort us: return us;
                case short sh: return sh;
                case string str: return int.TryParse(str, NumberStyles.Integer, CultureInfo.InvariantCulture, out var r) ? r : (int?)null;
                default:
                    try { return Convert.ToInt32(v, CultureInfo.InvariantCulture); } catch { return null; }
            }
        }

        internal static int? ToPort(object v)
        {
            if (v is string s)
                return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p) ? p : (int?)null;
            var n = ToInt(v);
            if (n == null) return null;
            int raw = n.Value & 0xFFFF;
            return PortsAreNetworkOrder ? ((raw & 0xFF) << 8) | (raw >> 8) : raw;
        }

        internal static IPAddress ToAddress(object v)
        {
            switch (v)
            {
                case null: return null;
                case IPAddress ip: return NetEndpoint.Normalize(ip);
                case byte[] b when b.Length == 4 || b.Length == 16: return NetEndpoint.Normalize(new IPAddress(b));
                case string s: return IPAddress.TryParse(s, out var p) ? NetEndpoint.Normalize(p) : null;
                case int i: return new IPAddress(BitConverter.GetBytes(i));
                case uint u: return new IPAddress(BitConverter.GetBytes(u));
                case long l: return new IPAddress(BitConverter.GetBytes((uint)l));
                default: return null;
            }
        }

        /// <summary>Case-insensitive field lookup over a name → value dictionary (fixture/offline use).</summary>
        public static Func<string, object> Fields(IDictionary<string, object> payload) =>
            name => payload.FirstOrDefault(kv => string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)).Value;
    }
}
