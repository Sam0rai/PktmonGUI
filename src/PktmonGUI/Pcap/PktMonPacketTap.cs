using System;
using System.Linq;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using PktmonGUI.Attribution;

namespace PktmonGUI.Pcap
{
    /// <summary>
    /// Saves a Live capture's packet bytes. pktmon's real-time mode prints text only, but the pktmon
    /// driver also emits every packet (with its raw bytes) through the Microsoft-Windows-PktMon ETW
    /// provider. This session enables that provider next to pktmon's own and writes the packets
    /// to a pcapng as they arrive. Verified against pktmon's text output: same packets, same
    /// PktGroupId/PktNumber, same direction and size.
    /// </summary>
    public sealed class PktMonPacketTap : IDisposable
    {
        public const string SessionName = "PktmonGUI-Packets";
        /// <summary>Config | Rundown | Payload, the set verified in the spike (tools/Spike-PktMonProvider.ps1).</summary>
        public const ulong Keywords = 0x13;
        private const int PacketEvent = 160, DropEvent = 170;
        private const int DirTagRx = 3, DirTagTx = 4;
        private const int PacketTypeEthernet = 1, PacketTypeRawIp = 3;

        private readonly LivePcapWriter _writer;
        private readonly long _maxBytes;
        private TraceEventSession _session;
        private Thread _pump;
        private long _skipped, _overCap;

        public PktMonPacketTap(string pcapPath, Func<int, string> componentName, long maxBytes)
        {
            _writer = new LivePcapWriter(pcapPath, componentName);
            _maxBytes = maxBytes;
        }

        public string Path => _writer.Path;
        public long Packets { get { lock (_writer) return _writer.Packets; } }
        /// <summary>Packets on media this writer can't label with a pcapng link type (not written).</summary>
        public long Skipped => Interlocked.Read(ref _skipped);
        /// <summary>Packets left out after the file reached its size cap.</summary>
        public long OverCap => Interlocked.Read(ref _overCap);
        public int EventsLost { get { try { return _session?.EventsLost ?? 0; } catch { return 0; } } }

        public static string EquivalentCommand =>
            $"logman start {SessionName} -ets -rt -p Microsoft-Windows-PktMon 0x13";

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

        public void Start()
        {
            StopLeftover();
            var session = new TraceEventSession(SessionName, null) { StopOnDispose = true, BufferSizeMB = 64 };
            try
            {
                session.EnableProvider(EtwAttributionSession.PktMon, TraceEventLevel.Informational, Keywords);
                var parser = new RegisteredTraceEventParser(session.Source);
                parser.All += OnEvent;
            }
            catch
            {
                session.Dispose();
                throw;
            }
            _session = session;
            _pump = new Thread(() =>
            {
                try { session.Source.Process(); } catch { }
            })
            { IsBackground = true, Name = "PktMon packet tap" };
            _pump.Start();
        }

        public enum WriteOutcome { NotAPacket, Written, Skipped, OverCap }

        private void OnEvent(TraceEvent e)
        {
            try
            {
                WriteOutcome r;
                lock (_writer) r = Write(_writer, (int)e.ID, name => Field(e, name), e.TimeStamp, _maxBytes);
                if (r == WriteOutcome.Skipped) Interlocked.Increment(ref _skipped);
                else if (r == WriteOutcome.OverCap) Interlocked.Increment(ref _overCap);
            }
            catch { /* one bad event must not end the capture */ }
        }

        /// <summary>
        /// One PktMon provider event → one pcapng packet. Event 160 is a packet, 170 a dropped packet;
        /// both carry PktGroupId, DirTag (3 Rx, 4 Tx), ComponentId, OriginalPayloadSize and the raw
        /// frame in Payload. Shared by the live tap and the replay tests.
        /// </summary>
        public static WriteOutcome Write(LivePcapWriter writer, int id, Func<string, object> field, DateTime time, long maxBytes)
        {
            if (id != PacketEvent && id != DropEvent) return WriteOutcome.NotAPacket;
            if (!(field("Payload") is byte[] payload) || payload.Length == 0) return WriteOutcome.NotAPacket;
            var link = LinkTypeOf(NetworkEventMapper.ToInt(field("PacketType")));
            if (link == null) return WriteOutcome.Skipped;
            if (writer.BytesWritten > maxBytes) return WriteOutcome.OverCap;
            int component = NetworkEventMapper.ToInt(field("ComponentId")) ?? 0;
            int original = NetworkEventMapper.ToInt(field("OriginalPayloadSize")) ?? payload.Length;
            int dir = NetworkEventMapper.ToInt(field("DirTag")) ?? 0;
            bool? inbound = dir == DirTagRx ? true : dir == DirTagTx ? false : (bool?)null;
            string comment = null;
            if (id == DropEvent)
            {
                int reason = NetworkEventMapper.ToInt(field("DropReason")) ?? 0;
                int location = NetworkEventMapper.ToInt(field("DropLocation")) ?? 0;
                comment = $"pktmon: dropped (reason {reason}, location 0x{location:X8})";
            }
            writer.Write(component, link.Value, time, payload, original, inbound, comment);
            return WriteOutcome.Written;
        }

        /// <summary>
        /// pktmon's PacketType to the pcapng link type for those bytes. 1 is an Ethernet frame.
        /// 3 is a bare IP packet with no link header, which is what mobile broadband (WWAN)
        /// adapters report and what pktmon's text output prints behind "ip: ". Null for anything
        /// else — native 802.11, for one — whose bytes this writer can't label.
        /// </summary>
        private static ushort? LinkTypeOf(int? packetType) =>
            packetType == PacketTypeEthernet ? FrameDecoder.LinkEthernet
            : packetType == PacketTypeRawIp ? FrameDecoder.LinkRawIp
            : (ushort?)null;

        private static object Field(TraceEvent e, string name)
        {
            int i = Array.FindIndex(e.PayloadNames, n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
            return i < 0 ? null : e.PayloadValue(i);
        }

        /// <summary>Flushes what ETW still holds, stops the session and closes the file.</summary>
        public void Stop()
        {
            var s = _session;
            _session = null;
            if (s != null)
            {
                // Real-time buffers are delivered on a timer; give the last ones a moment to arrive.
                try { s.Flush(); } catch { }
                Thread.Sleep(1200);
                try { s.Source.StopProcessing(); } catch { }
                try { s.Dispose(); } catch { }
                _pump?.Join(3000);
            }
            lock (_writer) _writer.Dispose();
        }

        public void Dispose() => Stop();
    }
}
