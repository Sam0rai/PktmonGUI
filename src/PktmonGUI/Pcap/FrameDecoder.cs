using System;
using System.Net;
using PktmonGUI.Model;

namespace PktmonGUI.Pcap
{
    /// <summary>
    /// Reads just enough of a raw frame (Ethernet → VLAN → IPv4/IPv6 → TCP/UDP) to fill the
    /// <see cref="PacketRecord"/> fields process attribution needs: addresses, ports, IP protocol,
    /// TCP flags, a DNS packet's question, and for non-IP frames the protocol name (so ARP, LLDP
    /// etc. get their reason).
    /// </summary>
    public static class FrameDecoder
    {
        public const ushort LinkEthernet = 1;
        public const ushort LinkRawIp = 101;
        public const ushort LinkIPv4 = 228;
        public const ushort LinkIPv6 = 229;

        /// <summary>Null when the link type isn't one pktmon produces for wired captures.</summary>
        public static PacketRecord Decode(byte[] f, ushort linkType, DateTime time)
        {
            var p = new PacketRecord { Time = time, OriginalSize = f.Length };
            try
            {
                switch (linkType)
                {
                    case LinkEthernet: Ethernet(p, f); break;
                    case LinkRawIp:
                    case LinkIPv4:
                    case LinkIPv6:
                        if (f.Length > 0 && f[0] >> 4 == 4) IPv4(p, f, 0);
                        else if (f.Length > 0 && f[0] >> 4 == 6) IPv6(p, f, 0);
                        break;
                    default: return null;
                }
            }
            catch (IndexOutOfRangeException) { /* truncated (snap length): keep what was read */ }
            catch (ArgumentException) { }
            if (p.Protocol == null) p.Protocol = p.EtherType ?? "?";
            return p;
        }

        private static ushort U16(byte[] b, int o) => (ushort)(b[o] << 8 | b[o + 1]);

        private static string Mac(byte[] b, int o) =>
            $"{b[o]:X2}-{b[o + 1]:X2}-{b[o + 2]:X2}-{b[o + 3]:X2}-{b[o + 4]:X2}-{b[o + 5]:X2}";

        private static void Ethernet(PacketRecord p, byte[] f)
        {
            p.DstMac = Mac(f, 0);
            p.SrcMac = Mac(f, 6);
            int o = 12;
            ushort type = U16(f, o);
            while (type == 0x8100 || type == 0x88A8 || type == 0x9100)
            {
                p.Vlan = U16(f, o + 2) & 0x0FFF;
                o += 4;
                type = U16(f, o);
            }
            o += 2;
            if (type < 0x0600)
            {
                // 802.3 length + LLC: STP (DSAP 0x42), CDP (SNAP to 01-00-0C-CC-CC-CC)
                p.EtherType = "802.3";
                p.Protocol = p.DstMac == "01-00-0C-CC-CC-CC" ? "CDP" : f.Length > o && f[o] == 0x42 ? "STP" : "LLC";
                return;
            }
            switch (type)
            {
                case 0x0800: p.EtherType = "IPv4"; IPv4(p, f, o); break;
                case 0x86DD: p.EtherType = "IPv6"; IPv6(p, f, o); break;
                case 0x0806: p.EtherType = "ARP"; p.Protocol = "ARP"; break;
                case 0x88CC: p.EtherType = "LLDP"; p.Protocol = "LLDP"; break;
                case 0x888E: p.EtherType = "EAPOL"; p.Protocol = "EAPOL"; break;
                default: p.EtherType = "0x" + type.ToString("x4"); break;
            }
        }

        private static void IPv4(PacketRecord p, byte[] f, int o)
        {
            p.EtherType = p.EtherType ?? "IPv4";
            int ihl = (f[o] & 0x0F) * 4;
            int proto = f[o + 9];
            bool firstFragment = (U16(f, o + 6) & 0x1FFF) == 0;
            p.SrcIp = new IPAddress(new[] { f[o + 12], f[o + 13], f[o + 14], f[o + 15] }).ToString();
            p.DstIp = new IPAddress(new[] { f[o + 16], f[o + 17], f[o + 18], f[o + 19] }).ToString();
            Transport(p, f, o + ihl, proto, firstFragment);
        }

        private static void IPv6(PacketRecord p, byte[] f, int o)
        {
            p.EtherType = p.EtherType ?? "IPv6";
            var src = new byte[16];
            var dst = new byte[16];
            Buffer.BlockCopy(f, o + 8, src, 0, 16);
            Buffer.BlockCopy(f, o + 24, dst, 0, 16);
            p.SrcIp = new IPAddress(src).ToString();
            p.DstIp = new IPAddress(dst).ToString();
            int next = f[o + 6];
            int at = o + 40;
            bool firstFragment = true;
            // Walk extension headers to the transport header.
            for (int guard = 0; guard < 8; guard++)
            {
                if (next == 0 || next == 43 || next == 60)      // hop-by-hop, routing, destination options
                {
                    int len = (f[at + 1] + 1) * 8;
                    next = f[at];
                    at += len;
                }
                else if (next == 44)                               // fragment
                {
                    firstFragment = (U16(f, at + 2) & 0xFFF8) == 0;
                    next = f[at];
                    at += 8;
                }
                else if (next == 51)                               // authentication header
                {
                    int len = (f[at + 1] + 2) * 4;
                    next = f[at];
                    at += len;
                }
                else break;
            }
            Transport(p, f, at, next, firstFragment);
        }

        private static void Transport(PacketRecord p, byte[] f, int o, int proto, bool firstFragment)
        {
            p.IpProtocol = proto;
            switch (proto)
            {
                case 6:
                    p.Protocol = "TCP";
                    if (!firstFragment) return;
                    p.SrcPort = U16(f, o);
                    p.DstPort = U16(f, o + 2);
                    p.TcpFlags = TcpFlagsOf(f[o + 13]);
                    break;
                case 17:
                    p.Protocol = "UDP";
                    if (!firstFragment) return;
                    p.SrcPort = U16(f, o);
                    p.DstPort = U16(f, o + 2);
                    if (p.SrcPort == 53 || p.DstPort == 53)
                    {
                        p.Protocol = "DNS";
                        p.Dns = Attribution.DnsQuestion.FromBytes(f, o + 8);
                    }
                    break;
                case 1: p.Protocol = "ICMP"; break;
                case 58: p.Protocol = "ICMPv6"; break;
                case 2: p.Protocol = "IGMP"; break;
                case 47: p.Protocol = "GRE"; break;
                case 50: p.Protocol = "ESP"; break;
                default: p.Protocol = "IP proto " + proto; break;
            }
            p.Source = p.SrcPort.HasValue ? p.SrcIp + "." + p.SrcPort : p.SrcIp;
            p.Destination = p.DstPort.HasValue ? p.DstIp + "." + p.DstPort : p.DstIp;
        }

        private static TcpFlags TcpFlagsOf(byte b)
        {
            var f = TcpFlags.None;
            if ((b & 0x01) != 0) f |= TcpFlags.FIN;
            if ((b & 0x02) != 0) f |= TcpFlags.SYN;
            if ((b & 0x04) != 0) f |= TcpFlags.RST;
            if ((b & 0x08) != 0) f |= TcpFlags.PSH;
            if ((b & 0x10) != 0) f |= TcpFlags.ACK;
            if ((b & 0x20) != 0) f |= TcpFlags.URG;
            if ((b & 0x40) != 0) f |= TcpFlags.ECE;
            if ((b & 0x80) != 0) f |= TcpFlags.CWR;
            return f;
        }
    }
}
