using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PktmonGUI.Pcap
{
    /// <summary>One pcapng block: type plus body (everything between the length fields).</summary>
    public sealed class PcapngBlock
    {
        public const uint SectionHeader = 0x0A0D0D0A;
        public const uint InterfaceDescription = 0x00000001;
        public const uint EnhancedPacket = 0x00000006;

        public PcapngBlock(uint type, byte[] body) { Type = type; Body = body; }
        public uint Type { get; }
        public byte[] Body { get; }
    }

    /// <summary>A pcapng option (code, value). Code 1 is opt_comment in every block type.</summary>
    public struct PcapngOption
    {
        public const ushort EndOfOptions = 0;
        public const ushort Comment = 1;
        public const ushort IfTsResol = 9;

        public PcapngOption(ushort code, byte[] value) { Code = code; Value = value; }
        public ushort Code { get; }
        public byte[] Value { get; }
    }

    /// <summary>An Enhanced Packet Block, split into its fields.</summary>
    public sealed class EnhancedPacket
    {
        public uint InterfaceId { get; set; }
        public ulong Timestamp { get; set; }
        public uint OriginalLength { get; set; }
        public byte[] Data { get; set; }
        public List<PcapngOption> Options { get; set; } = new List<PcapngOption>();
    }

    /// <summary>
    /// Minimal pcapng reader/writer (https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html).
    /// Enough to walk the blocks etl2pcap writes and add per-packet comments; blocks it doesn't
    /// need to change are copied through byte for byte. Little-endian sections only, which is
    /// what Windows (and etl2pcap) produce.
    /// </summary>
    public static class Pcapng
    {
        private const uint ByteOrderMagic = 0x1A2B3C4D;

        public static IEnumerable<PcapngBlock> ReadBlocks(Stream s)
        {
            var header = new byte[8];
            while (true)
            {
                int n = ReadFully(s, header, 8);
                if (n == 0) yield break;
                if (n < 8) throw new InvalidDataException("pcapng: truncated block header");
                uint type = BitConverter.ToUInt32(header, 0);
                uint length = BitConverter.ToUInt32(header, 4);
                if (type == PcapngBlock.SectionHeader)
                {
                    // The byte-order magic follows; a big-endian section would have its length byte-swapped too.
                    var magic = new byte[4];
                    if (ReadFully(s, magic, 4) < 4) throw new InvalidDataException("pcapng: truncated section header");
                    uint m = BitConverter.ToUInt32(magic, 0);
                    if (m != ByteOrderMagic)
                        throw new NotSupportedException(m == 0x4D3C2B1A ? "Big-endian pcapng isn't supported." : "Not a pcapng file.");
                    if (length < 28 || length % 4 != 0) throw new InvalidDataException("pcapng: bad section header length");
                    var rest = new byte[length - 12];
                    Buffer.BlockCopy(magic, 0, rest, 0, 4);
                    if (ReadFully(s, rest, rest.Length - 4, 4) < rest.Length - 4) throw new InvalidDataException("pcapng: truncated section header");
                    ReadTrailer(s, length);
                    yield return new PcapngBlock(type, rest);
                    continue;
                }
                if (length < 12 || length % 4 != 0) throw new InvalidDataException($"pcapng: bad block length {length}");
                var body = new byte[length - 12];
                if (ReadFully(s, body, body.Length) < body.Length) throw new InvalidDataException("pcapng: truncated block");
                ReadTrailer(s, length);
                yield return new PcapngBlock(type, body);
            }
        }

        private static void ReadTrailer(Stream s, uint length)
        {
            var t = new byte[4];
            if (ReadFully(s, t, 4) < 4 || BitConverter.ToUInt32(t, 0) != length)
                throw new InvalidDataException("pcapng: block length mismatch");
        }

        private static int ReadFully(Stream s, byte[] buf, int count, int offset = 0)
        {
            int total = 0;
            while (total < count)
            {
                int n = s.Read(buf, offset + total, count - total);
                if (n == 0) break;
                total += n;
            }
            return total;
        }

        /// <summary>
        /// Joins pcapng files, in order, into one single-section file: the first file's section header,
        /// each distinct interface once, and every packet re-pointed at its interface's new ID. (Files
        /// simply placed end to end are valid pcapng too, but not every reader handles several sections.)
        /// Returns the number of packets written.
        /// </summary>
        public static long Join(IReadOnlyList<string> inputs, string output)
        {
            const uint InterfaceStatistics = 0x00000005, SimplePacket = 0x00000003;
            long packets = 0;
            var ids = new Dictionary<string, uint>(); // IDB body (base64) → ID in the output
            var temp = output + ".tmp-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            try
            {
                using (var outStream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
                {
                    bool wroteHeader = false;
                    foreach (var input in inputs)
                    {
                        var map = new List<uint>(); // this section's interface IDs → output IDs
                        using (var inStream = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16))
                            foreach (var block in ReadBlocks(inStream))
                            {
                                switch (block.Type)
                                {
                                    case PcapngBlock.SectionHeader:
                                        if (map.Count > 0) throw new NotSupportedException($"{Path.GetFileName(input)} has more than one section.");
                                        if (wroteHeader) continue;
                                        // Section length "unspecified": the joined section is longer than the first file's.
                                        var shb = (byte[])block.Body.Clone();
                                        Buffer.BlockCopy(BitConverter.GetBytes(-1L), 0, shb, 8, 8);
                                        WriteBlock(outStream, block.Type, shb);
                                        wroteHeader = true;
                                        continue;
                                    case PcapngBlock.InterfaceDescription:
                                        var key = Convert.ToBase64String(block.Body);
                                        if (!ids.TryGetValue(key, out var id))
                                        {
                                            ids[key] = id = (uint)ids.Count;
                                            WriteBlock(outStream, block.Type, block.Body);
                                        }
                                        map.Add(id);
                                        continue;
                                    case PcapngBlock.EnhancedPacket:
                                    case InterfaceStatistics:
                                        // Both start with the interface ID.
                                        var body = (byte[])block.Body.Clone();
                                        var local = BitConverter.ToUInt32(body, 0);
                                        if (local >= map.Count) throw new InvalidDataException($"{Path.GetFileName(input)}: a block names interface {local}, which isn't described.");
                                        Buffer.BlockCopy(BitConverter.GetBytes(map[(int)local]), 0, body, 0, 4);
                                        WriteBlock(outStream, block.Type, body);
                                        if (block.Type == PcapngBlock.EnhancedPacket) packets++;
                                        continue;
                                    case SimplePacket:
                                        throw new NotSupportedException($"{Path.GetFileName(input)} has simple packet blocks, which can't be joined.");
                                    default:
                                        WriteBlock(outStream, block.Type, block.Body);
                                        continue;
                                }
                            }
                    }
                    if (!wroteHeader) throw new InvalidDataException("Nothing to join: no pcapng section header in the input.");
                }
                if (File.Exists(output)) File.Delete(output);
                File.Move(temp, output);
            }
            finally
            {
                if (File.Exists(temp)) File.Delete(temp);
            }
            return packets;
        }

        public static void WriteBlock(Stream s, uint type, byte[] body)
        {
            uint length = (uint)(12 + body.Length);
            s.Write(BitConverter.GetBytes(type), 0, 4);
            s.Write(BitConverter.GetBytes(length), 0, 4);
            s.Write(body, 0, body.Length);
            s.Write(BitConverter.GetBytes(length), 0, 4);
        }

        // ---- Options ------------------------------------------------------------------

        public static List<PcapngOption> ReadOptions(byte[] buf, int offset)
        {
            var list = new List<PcapngOption>();
            while (offset + 4 <= buf.Length)
            {
                ushort code = BitConverter.ToUInt16(buf, offset);
                ushort len = BitConverter.ToUInt16(buf, offset + 2);
                if (code == PcapngOption.EndOfOptions) break;
                if (offset + 4 + len > buf.Length) break; // malformed: keep what we have
                var v = new byte[len];
                Buffer.BlockCopy(buf, offset + 4, v, 0, len);
                list.Add(new PcapngOption(code, v));
                offset += 4 + Pad4(len);
            }
            return list;
        }

        public static void WriteOptions(MemoryStream ms, IEnumerable<PcapngOption> options)
        {
            bool any = false;
            foreach (var o in options)
            {
                any = true;
                ms.Write(BitConverter.GetBytes(o.Code), 0, 2);
                ms.Write(BitConverter.GetBytes((ushort)o.Value.Length), 0, 2);
                ms.Write(o.Value, 0, o.Value.Length);
                ms.Write(new byte[Pad4(o.Value.Length) - o.Value.Length], 0, Pad4(o.Value.Length) - o.Value.Length);
            }
            if (any) ms.Write(new byte[4], 0, 4); // opt_endofopt
        }

        public static PcapngOption CommentOption(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            if (bytes.Length > ushort.MaxValue) Array.Resize(ref bytes, ushort.MaxValue);
            return new PcapngOption(PcapngOption.Comment, bytes);
        }

        public static IEnumerable<string> Comments(IEnumerable<PcapngOption> options)
        {
            foreach (var o in options)
                if (o.Code == PcapngOption.Comment) yield return Encoding.UTF8.GetString(o.Value);
        }

        internal static int Pad4(int n) => (n + 3) & ~3;

        // ---- Enhanced Packet Block ---------------------------------------------------------

        public static EnhancedPacket ParseEnhancedPacket(byte[] body)
        {
            if (body.Length < 20) throw new InvalidDataException("pcapng: short Enhanced Packet Block");
            uint capLen = BitConverter.ToUInt32(body, 12);
            if (20 + capLen > body.Length) throw new InvalidDataException("pcapng: packet data overruns its block");
            var data = new byte[capLen];
            Buffer.BlockCopy(body, 20, data, 0, (int)capLen);
            return new EnhancedPacket
            {
                InterfaceId = BitConverter.ToUInt32(body, 0),
                Timestamp = ((ulong)BitConverter.ToUInt32(body, 4) << 32) | BitConverter.ToUInt32(body, 8),
                OriginalLength = BitConverter.ToUInt32(body, 16),
                Data = data,
                Options = ReadOptions(body, 20 + Pad4((int)capLen)),
            };
        }

        public static byte[] BuildEnhancedPacket(EnhancedPacket p)
        {
            using (var ms = new MemoryStream(32 + p.Data.Length))
            {
                ms.Write(BitConverter.GetBytes(p.InterfaceId), 0, 4);
                ms.Write(BitConverter.GetBytes((uint)(p.Timestamp >> 32)), 0, 4);
                ms.Write(BitConverter.GetBytes((uint)p.Timestamp), 0, 4);
                ms.Write(BitConverter.GetBytes((uint)p.Data.Length), 0, 4);
                ms.Write(BitConverter.GetBytes(p.OriginalLength), 0, 4);
                ms.Write(p.Data, 0, p.Data.Length);
                ms.Write(new byte[Pad4(p.Data.Length) - p.Data.Length], 0, Pad4(p.Data.Length) - p.Data.Length);
                WriteOptions(ms, p.Options);
                return ms.ToArray();
            }
        }

        // ---- Section / interface headers -----------------------------------------------------

        /// <summary>Section header body with a comment added and the section length set to "unspecified" (it changes).</summary>
        public static byte[] AddSectionComment(byte[] shbBody, string comment, string replacePrefix = null)
        {
            // magic(4) major(2) minor(2) sectionLength(8) options...
            var options = ReadOptions(shbBody, 16);
            if (replacePrefix != null)
                options.RemoveAll(o => o.Code == PcapngOption.Comment && Encoding.UTF8.GetString(o.Value).StartsWith(replacePrefix, StringComparison.Ordinal));
            options.Add(CommentOption(comment));
            using (var ms = new MemoryStream())
            {
                ms.Write(shbBody, 0, 8);
                ms.Write(BitConverter.GetBytes(-1L), 0, 8);
                WriteOptions(ms, options);
                return ms.ToArray();
            }
        }

        public sealed class InterfaceInfo
        {
            public ushort LinkType { get; set; }
            /// <summary>Timestamp units per second (if_tsresol; default 10^6).</summary>
            public double UnitsPerSecond { get; set; } = 1e6;
            public byte TsResol { get; set; } = 6;
        }

        public static InterfaceInfo ParseInterface(byte[] idbBody)
        {
            var info = new InterfaceInfo { LinkType = BitConverter.ToUInt16(idbBody, 0) };
            foreach (var o in ReadOptions(idbBody, 8))
                if (o.Code == PcapngOption.IfTsResol && o.Value.Length >= 1)
                {
                    byte v = o.Value[0];
                    info.TsResol = v;
                    info.UnitsPerSecond = (v & 0x80) == 0 ? Math.Pow(10, v) : Math.Pow(2, v & 0x7F);
                }
            return info;
        }

        /// <summary>pcapng timestamps are UTC since 1970; PktmonGUI's packet times are local.</summary>
        public static DateTime ToLocalTime(ulong timestamp, InterfaceInfo iface)
        {
            long ticks;
            if ((iface.TsResol & 0x80) == 0 && iface.TsResol <= 7)
                ticks = (long)timestamp * (long)Math.Pow(10, 7 - iface.TsResol);
            else if ((iface.TsResol & 0x80) == 0)
                ticks = (long)(timestamp / (ulong)Math.Pow(10, iface.TsResol - 7));
            else
                ticks = (long)(timestamp / iface.UnitsPerSecond * 1e7);
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddTicks(ticks).ToLocalTime();
        }
    }
}
