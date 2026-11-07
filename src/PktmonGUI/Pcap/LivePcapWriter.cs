using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PktmonGUI.Pcap
{
    /// <summary>
    /// Writes a pcapng as packets arrive: one interface per pktmon component (named after the
    /// adapter), 100 ns timestamps, the direction in epb_flags, and a comment on dropped packets.
    /// Process comments are added when the capture stops (<see cref="ProcessCommenter"/>).
    /// </summary>
    public sealed class LivePcapWriter : IDisposable
    {
        private const ushort OptIfName = 2, OptIfDescription = 3, OptShbOs = 3, OptShbUserAppl = 4, OptEpbFlags = 2;
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private readonly FileStream _file;
        /// <summary>Keyed by component and link type: see <see cref="Interface"/>.</summary>
        private readonly Dictionary<long, uint> _interfaces = new Dictionary<long, uint>();
        private readonly Func<int, string> _componentName;

        public LivePcapWriter(string path, Func<int, string> componentName)
        {
            Path = path;
            _componentName = componentName;
            _file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read, 1 << 16);
            using (var ms = new MemoryStream())
            {
                ms.Write(BitConverter.GetBytes(0x1A2B3C4Du), 0, 4); // byte-order magic
                ms.Write(BitConverter.GetBytes((ushort)1), 0, 2);   // major
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);   // minor
                ms.Write(BitConverter.GetBytes(-1L), 0, 8);         // section length: unspecified
                Pcapng.WriteOptions(ms, new[]
                {
                    Text(OptShbOs, Environment.OSVersion.VersionString),
                    Text(OptShbUserAppl, "PktmonGUI (live capture from the Microsoft-Windows-PktMon ETW provider)"),
                });
                Pcapng.WriteBlock(_file, PcapngBlock.SectionHeader, ms.ToArray());
            }
        }

        public string Path { get; }
        public long Packets { get; private set; }
        public long BytesWritten => _file.CanWrite ? _file.Position : _written;
        private long _written;

        private static PcapngOption Text(ushort code, string s) => new PcapngOption(code, Encoding.UTF8.GetBytes(s ?? ""));

        /// <summary>
        /// The interface index for a component's packets. A pcapng interface carries one link type,
        /// so a component that reports more than one (it shouldn't: an adapter has a single medium)
        /// gets an interface per link type rather than frames labelled with the wrong one.
        /// </summary>
        private uint Interface(int componentId, ushort linkType)
        {
            long key = (long)componentId << 16 | linkType;
            if (_interfaces.TryGetValue(key, out var index)) return index;
            index = (uint)_interfaces.Count;
            using (var ms = new MemoryStream())
            {
                ms.Write(BitConverter.GetBytes(linkType), 0, 2);
                ms.Write(new byte[2], 0, 2);                         // reserved
                ms.Write(BitConverter.GetBytes(0u), 0, 4);           // snaplen: none
                var options = new List<PcapngOption> { Text(OptIfName, "pktmon component " + componentId) };
                // The adapter name comes from a resolver outside this class; losing it costs a
                // description, so it must not cost the capture.
                string name = null;
                try { name = _componentName?.Invoke(componentId); } catch { }
                if (!string.IsNullOrEmpty(name)) options.Add(Text(OptIfDescription, name));
                options.Add(new PcapngOption(PcapngOption.IfTsResol, new byte[] { 7 })); // 10^-7 s, ETW's resolution
                Pcapng.WriteOptions(ms, options);
                Pcapng.WriteBlock(_file, PcapngBlock.InterfaceDescription, ms.ToArray());
            }
            // Only once the block is on disk: a throw on the way here must not leave the interface
            // marked written, or every later packet would reference an interface the file never
            // describes — and the tap swallows write errors, so that would pass unnoticed.
            _interfaces[key] = index;
            return index;
        }

        /// <param name="linkType">How <paramref name="data"/> is framed: Ethernet, or raw IP on media with no link header.</param>
        /// <param name="inbound">true Rx, false Tx, null unknown.</param>
        public void Write(int componentId, ushort linkType, DateTime time, byte[] data, int originalLength, bool? inbound, string comment)
        {
            var epb = new EnhancedPacket
            {
                InterfaceId = Interface(componentId, linkType),
                Timestamp = (ulong)(time.ToUniversalTime() - Epoch).Ticks,
                OriginalLength = (uint)Math.Max(originalLength, data.Length),
                Data = data,
            };
            if (inbound.HasValue)
                epb.Options.Add(new PcapngOption(OptEpbFlags, BitConverter.GetBytes(inbound.Value ? 1u : 2u)));
            if (comment != null) epb.Options.Add(Pcapng.CommentOption(comment));
            Pcapng.WriteBlock(_file, PcapngBlock.EnhancedPacket, Pcapng.BuildEnhancedPacket(epb));
            Packets++;
        }

        public void Dispose()
        {
            try { _file.Flush(); _written = _file.Position; } catch { }
            _file.Dispose();
        }
    }
}
