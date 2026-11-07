using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PktmonGUI.Attribution;
using PktmonGUI.Model;

namespace PktmonGUI.Pcap
{
    public sealed class CommentResult
    {
        public int Packets { get; set; }
        public int Commented { get; set; }
        public int WithProcess { get; set; }
        public int NoProcess { get; set; }
        public int Unknown { get; set; }
        public int Undecoded { get; set; }

        public override string ToString() =>
            $"{WithProcess:N0} of {Packets:N0} packets have a process" +
            (NoProcess > 0 ? $", {NoProcess:N0} have none (ARP, ICMP, …)" : "") +
            (Unknown > 0 ? $", {Unknown:N0} unknown" : "") +
            (Undecoded > 0 ? $", {Undecoded:N0} not decodable" : "");
    }

    /// <summary>
    /// Adds a "Process: …" comment to every packet of a pcapng (etl2pcap output, or a Live capture
    /// saved by <see cref="PktMonPacketTap"/>), using the attribution recorded during the capture
    /// (<c>name.attribution.json</c>). Wireshark shows it under Packet comments and as
    /// <c>frame.comment</c>. Each packet is matched by its own addresses, ports and timestamp.
    /// </summary>
    public static class ProcessCommenter
    {
        public const string Prefix = "Process: ";
        public const string PathPrefix = "Process path: ";

        private static bool IsOurs(string comment) =>
            comment.StartsWith(Prefix, StringComparison.Ordinal) || comment.StartsWith(PathPrefix, StringComparison.Ordinal);

        /// <summary>
        /// The second comment: where the process ran from. A process name alone can be spoofed
        /// (chrome.exe running from C:\Windows\Temp); the full image path shows it.
        /// </summary>
        public static string PathCommentFor(ProcessAttribution a)
        {
            switch (a.State)
            {
                case AttributionState.Resolved:
                    return PathPrefix + (a.Path ?? "unknown (the process exited before its path could be read)") +
                           (a.RequesterPid == null ? "" : " for " + (a.RequesterPath ?? $"unknown path (PID {a.RequesterPid})"));
                case AttributionState.System:
                    return PathPrefix + "kernel (System, PID 4)";
                case AttributionState.NoProcess:
                    return PathPrefix + "none";
                default:
                    return PathPrefix + "unknown";
            }
        }

        /// <summary>
        /// The per-packet comment, e.g. "Process: curl.exe (PID 20560)", or for DNS the DNS Client
        /// service sent: "Process: svchost.exe (PID 3152; Dnscache) for curl.exe (PID 20560)".
        /// </summary>
        public static string CommentFor(ProcessAttribution a)
        {
            switch (a.State)
            {
                case AttributionState.Resolved:
                    return (a.Name == null ? Prefix + $"unknown name (PID {a.Pid})" : Prefix + $"{a.Name} (PID {a.Pid}{(string.IsNullOrEmpty(a.Services) ? "" : "; " + a.Services)})") +
                           (a.RequesterPid == null ? "" : $" for {a.RequesterName ?? "unknown name"} (PID {a.RequesterPid})");
                case AttributionState.System:
                    return Prefix + $"System (PID 4; {a.Reason ?? "kernel"})";
                case AttributionState.NoProcess:
                    return Prefix + $"none ({a.Reason})";
                default:
                    return Prefix + "unknown" + (a.Reason == null ? "" : $" ({a.Reason})");
            }
        }

        /// <summary>
        /// Writes <paramref name="output"/> (which may equal <paramref name="input"/>) with process comments.
        /// </summary>
        public static CommentResult Annotate(string input, string output, AttributionSnapshot snapshot, string sourceName)
        {
            var engine = AttributionEngine.FromSnapshot(snapshot);
            var result = new CommentResult();
            var temp = output + ".tmp-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            try
            {
                using (var inStream = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16))
                using (var outStream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
                {
                    var interfaces = new List<Pcapng.InterfaceInfo>();
                    foreach (var block in Pcapng.ReadBlocks(inStream))
                    {
                        switch (block.Type)
                        {
                            case PcapngBlock.SectionHeader:
                                interfaces.Clear(); // interface IDs are per section
                                Pcapng.WriteBlock(outStream, block.Type, Pcapng.AddSectionComment(block.Body,
                                    $"Packet comments \"{Prefix}…\" and \"{PathPrefix}…\" added by PktmonGUI from {sourceName}: the process that owned each packet's socket " +
                                    "and the full path of its image, matched per flow from Kernel-Network ETW events and the connection table recorded during the capture. " +
                                    "DNS sent by the DNS Client service also names the process that asked for it, from DNS-Client ETW events.",
                                    replacePrefix: "Packet comments \"" + Prefix));
                                break;
                            case PcapngBlock.InterfaceDescription:
                                interfaces.Add(Pcapng.ParseInterface(block.Body));
                                Pcapng.WriteBlock(outStream, block.Type, block.Body);
                                break;
                            case PcapngBlock.EnhancedPacket:
                                Pcapng.WriteBlock(outStream, block.Type, Comment(block.Body, interfaces, engine, result));
                                break;
                            default:
                                Pcapng.WriteBlock(outStream, block.Type, block.Body);
                                break;
                        }
                    }
                }
                if (File.Exists(output)) File.Delete(output);
                File.Move(temp, output);
            }
            finally
            {
                if (File.Exists(temp)) File.Delete(temp);
            }
            return result;
        }

        private static byte[] Comment(byte[] body, List<Pcapng.InterfaceInfo> interfaces, AttributionEngine engine, CommentResult result)
        {
            result.Packets++;
            var epb = Pcapng.ParseEnhancedPacket(body);
            var iface = epb.InterfaceId < interfaces.Count ? interfaces[(int)epb.InterfaceId] : new Pcapng.InterfaceInfo { LinkType = FrameDecoder.LinkEthernet };
            var packet = FrameDecoder.Decode(epb.Data, iface.LinkType, Pcapng.ToLocalTime(epb.Timestamp, iface));
            if (packet == null) { result.Undecoded++; return body; }

            // No direction in etl2pcap's output; infer it from which end is this machine.
            if (packet.SrcIp != null && packet.DstIp != null)
            {
                bool srcLocal = engine.IsLocal(System.Net.IPAddress.Parse(packet.SrcIp));
                bool dstLocal = engine.IsLocal(System.Net.IPAddress.Parse(packet.DstIp));
                packet.Direction = srcLocal && !dstLocal ? Direction.Tx : dstLocal && !srcLocal ? Direction.Rx : Direction.Unknown;
            }

            var a = engine.Observe(packet);
            switch (a.State)
            {
                case AttributionState.Resolved:
                case AttributionState.System: result.WithProcess++; break;
                case AttributionState.NoProcess: result.NoProcess++; break;
                default: result.Unknown++; break;
            }

            // Replace earlier PktmonGUI comments (re-conversion), keep anyone else's. Ours go first and
            // always in the same order, so a Wireshark custom column on frame.comment can pick
            // occurrence 1 (process) or 2 (path) whether or not a drop note follows.
            var others = epb.Options.Where(o => !(o.Code == PcapngOption.Comment && IsOurs(Encoding.UTF8.GetString(o.Value)))).ToList();
            epb.Options = new List<PcapngOption> { Pcapng.CommentOption(CommentFor(a)), Pcapng.CommentOption(PathCommentFor(a)) };
            epb.Options.AddRange(others);
            result.Commented++;
            return Pcapng.BuildEnhancedPacket(epb);
        }
    }
}
