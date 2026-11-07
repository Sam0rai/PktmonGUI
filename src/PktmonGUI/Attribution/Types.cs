using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace PktmonGUI.Attribution
{
    public enum FlowProto { Tcp, Udp }

    public enum FlowEventKind { Connect, Accept, Disconnect, Reconnect, Fail, Send, Receive }

    /// <summary>An IP address and port, normalized so pktmon text and ETW/table values compare equal.</summary>
    public struct NetEndpoint : IEquatable<NetEndpoint>
    {
        public NetEndpoint(IPAddress ip, int port)
        {
            Ip = Normalize(ip);
            Port = port;
        }

        public IPAddress Ip { get; }
        public int Port { get; }

        public bool IsUnspecified => Ip == null || Ip.Equals(IPAddress.Any) || Ip.Equals(IPAddress.IPv6Any);

        /// <summary>IPv4-mapped IPv6 becomes IPv4; IPv6 scope IDs are dropped (pktmon doesn't print them).</summary>
        public static IPAddress Normalize(IPAddress ip)
        {
            if (ip == null) return null;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (ip.IsIPv4MappedToIPv6) return ip.MapToIPv4();
                if (ip.ScopeId != 0) return new IPAddress(ip.GetAddressBytes());
            }
            return ip;
        }

        public static bool TryCreate(string ip, int? port, out NetEndpoint ep)
        {
            ep = default;
            if (ip == null || !port.HasValue || !IPAddress.TryParse(ip, out var addr)) return false;
            ep = new NetEndpoint(addr, port.Value);
            return true;
        }

        public string Key => (Ip?.ToString() ?? "*") + "#" + Port.ToString(CultureInfo.InvariantCulture);

        public override string ToString() =>
            Ip == null ? "*:" + Port : Ip.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Ip}]:{Port}" : $"{Ip}:{Port}";

        public bool Equals(NetEndpoint other) => Port == other.Port && Equals(Ip, other.Ip);
        public override bool Equals(object obj) => obj is NetEndpoint e && Equals(e);
        public override int GetHashCode() => (Ip?.GetHashCode() ?? 0) * 397 ^ Port;
    }

    /// <summary>One socket-level event from Microsoft-Windows-Kernel-Network.</summary>
    public sealed class FlowEvent
    {
        public FlowProto Proto { get; set; }
        public FlowEventKind Kind { get; set; }
        public int Pid { get; set; }
        public NetEndpoint Local { get; set; }
        public NetEndpoint Remote { get; set; }
        public DateTime Time { get; set; }

        public override string ToString() => $"{Time:HH:mm:ss.fff} {Proto} {Kind} pid {Pid} {Local} ↔ {Remote}";
    }

    public enum AttributionState { Pending, Resolved, System, NoProcess, Unknown }

    /// <summary>Which process a packet belongs to, and how PktmonGUI knows.</summary>
    public sealed class ProcessAttribution
    {
        public AttributionState State { get; set; }
        public int? Pid { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string Services { get; set; }
        /// <summary>How it was attributed: "TCP connect event", "connection table", "UDP port binding", ...</summary>
        public string Source { get; set; }
        /// <summary>Why there's no process, or a hint such as "SMB (kernel)".</summary>
        public string Reason { get; set; }

        /// <summary>
        /// DNS sent by the DNS Client service (Dnscache): the process that asked for the name, from
        /// Dnscache's own ETW event. The socket is Dnscache's, so <see cref="Pid"/> stays svchost's.
        /// </summary>
        public int? RequesterPid { get; set; }
        public string RequesterName { get; set; }
        public string RequesterPath { get; set; }
        /// <summary>Why a DNS packet Dnscache sent has no requester.</summary>
        public string RequesterNote { get; set; }

        public bool IsFinal => State != AttributionState.Pending;

        /// <summary>"curl.exe · 20560", or null when there's no requester.</summary>
        public string RequesterText =>
            RequesterPid == null ? null : RequesterName == null ? $"PID {RequesterPid} (name unknown)" : $"{RequesterName} · {RequesterPid}";

        /// <summary>Grid text: "chrome.exe · 4312", "svchost (Dnscache) · 3152 for curl.exe · 20560", "System · SMB", "…", "—", "?".</summary>
        public string Text
        {
            get
            {
                switch (State)
                {
                    case AttributionState.Pending: return "…";
                    case AttributionState.NoProcess: return "—";
                    case AttributionState.Unknown: return "?";
                    case AttributionState.System: return Reason == null ? "System · 4" : "System · " + Reason;
                    default:
                        string owner;
                        if (Name == null) owner = $"PID {Pid} (name unknown)";
                        else if (!string.IsNullOrEmpty(Services) && Name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                            owner = $"svchost ({Services}) · {Pid}";
                        else owner = $"{Name} · {Pid}";
                        return RequesterPid == null ? owner : owner + " for " + RequesterText;
                }
            }
        }

        public string Tooltip
        {
            get
            {
                switch (State)
                {
                    case AttributionState.Pending: return "Waiting for the ETW event that names this flow's process";
                    case AttributionState.NoProcess: return "No local process: " + Reason;
                    case AttributionState.Unknown: return "No process found for this flow" + (Reason == null ? "" : ": " + Reason);
                    default:
                        return (Path ?? Name) +
                               (RequesterPid == null ? "" : $"\nfor {RequesterPath ?? RequesterName ?? "a process whose name is unknown"} (PID {RequesterPid}), which asked the DNS Client service for this name") +
                               (Source == null ? "" : "\nAttributed by " + Source);
                }
            }
        }

        public static ProcessAttribution Pending() => new ProcessAttribution { State = AttributionState.Pending };
        public static ProcessAttribution None(string reason) => new ProcessAttribution { State = AttributionState.NoProcess, Reason = reason };
        public static ProcessAttribution NotFound(string reason = null) => new ProcessAttribution { State = AttributionState.Unknown, Reason = reason };
    }

    /// <summary>Time source, injectable so pending/timeout behaviour can be tested.</summary>
    public interface IClock { DateTime Now { get; } }

    public sealed class SystemClock : IClock
    {
        public static readonly SystemClock Instance = new SystemClock();
        public DateTime Now => DateTime.Now;
    }
}
