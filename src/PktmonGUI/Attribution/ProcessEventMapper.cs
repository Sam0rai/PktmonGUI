using System.Text;

namespace PktmonGUI.Attribution
{
    /// <summary>
    /// Microsoft-Windows-Kernel-Process ProcessStart (event 1): its ImageName, the full path of the
    /// process's image, read from the raw payload. The kernel writes it as the process is created,
    /// so even a process that exits a millisecond later (curl) has its path. TraceEvent's decoder
    /// can't reach it: from template version 3 on it follows a SID, and decoding stops there.
    /// </summary>
    public static class ProcessEventMapper
    {
        /// <summary>
        /// A <c>\Device\HarddiskVolumeN\...</c> path (see <see cref="DevicePaths"/>), or null when the
        /// payload isn't laid out as expected.
        /// </summary>
        public static string StartImageName(byte[] payload, int version)
        {
            // Fields before ImageName, packed as ETW writes them:
            // v0:   ProcessID u32, CreateTime u64, ParentProcessID u32, SessionID u32
            // v1-2: ... + Flags u32
            // v3-4: ProcessID u32, ProcessSequenceNumber u64, CreateTime u64, ParentProcessID u32,
            //       ParentProcessSequenceNumber u64, SessionID u32, Flags u32, ProcessTokenElevationType u32,
            //       ProcessTokenIsElevated u32, then the MandatoryLabel SID. Later versions add fields at the end.
            int o = version == 0 ? 20 : version <= 2 ? 24 : 48;
            if (payload == null || payload.Length < o + 2) return null;
            if (version >= 3 && !(payload[o] == '\\' && payload[o + 1] == 0))   // no SID: the path starts right away
            {
                // A SID: revision 1, sub-authority count, 6-byte authority, then 4 bytes per sub-authority.
                if (payload.Length < o + 8 || payload[o] != 1 || payload[o + 1] > 15) return null;
                o += 8 + 4 * payload[o + 1];
            }
            int end = o;
            while (end + 1 < payload.Length && (payload[end] != 0 || payload[end + 1] != 0)) end += 2;
            if (end == o || end + 1 >= payload.Length) return null;   // empty, or no terminator
            var path = Encoding.Unicode.GetString(payload, o, end - o);
            return path.IndexOf('\\') >= 0 ? path : null;
        }
    }
}
