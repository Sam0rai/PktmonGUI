using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace PktmonGUI.Attribution
{
    public sealed class TableConnection
    {
        public FlowProto Proto { get; set; }
        public NetEndpoint Local { get; set; }
        /// <summary>Null for UDP (the table has no remote side) and for listening TCP sockets.</summary>
        public NetEndpoint? Remote { get; set; }
        public int Pid { get; set; }
        public bool Listening { get; set; }
    }

    public sealed class ProcessSnapshotEntry
    {
        public int Pid { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public DateTime? Start { get; set; }
    }

    /// <summary>
    /// What's already there when a capture starts: open sockets with their owning PID
    /// (connections opened before the ETW session produce no connect event), running
    /// processes, and which services each svchost hosts.
    /// </summary>
    public static class SystemSeeder
    {
        // ---- Connection tables (iphlpapi) ----------------------------------------------

        private const int AF_INET = 2, AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int UDP_TABLE_OWNER_PID = 1;
        private const int MIB_TCP_STATE_LISTEN = 2;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

        public static List<TableConnection> Connections()
        {
            var list = new List<TableConnection>();
            try { ReadTcp(AF_INET, list); } catch { }
            try { ReadTcp(AF_INET6, list); } catch { }
            try { ReadUdp(AF_INET, list); } catch { }
            try { ReadUdp(AF_INET6, list); } catch { }
            return list;
        }

        private delegate uint TableFn(IntPtr t, ref int size, bool order, int af, int cls, uint reserved);

        private static IntPtr Fetch(TableFn fn, int af, int cls)
        {
            int size = 0;
            fn(IntPtr.Zero, ref size, false, af, cls, 0);
            for (int attempt = 0; attempt < 4; attempt++)
            {
                size += 4096;
                var buf = Marshal.AllocHGlobal(size);
                uint rc = fn(buf, ref size, false, af, cls, 0);
                if (rc == 0) return buf;
                Marshal.FreeHGlobal(buf);
                if (rc != 122 /* ERROR_INSUFFICIENT_BUFFER */) return IntPtr.Zero;
            }
            return IntPtr.Zero;
        }

        /// <summary>Table ports sit in the low 16 bits in network byte order.</summary>
        internal static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

        private static void ReadTcp(int af, List<TableConnection> list)
        {
            var buf = Fetch(GetExtendedTcpTable, af, TCP_TABLE_OWNER_PID_ALL);
            if (buf == IntPtr.Zero) return;
            try
            {
                int n = Marshal.ReadInt32(buf);
                var p = buf + 4;
                for (int i = 0; i < n; i++)
                {
                    if (af == AF_INET)
                    {
                        // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (6 × DWORD)
                        uint state = (uint)Marshal.ReadInt32(p);
                        var la = new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(p + 4)));
                        int lp = Port((uint)Marshal.ReadInt32(p + 8));
                        var ra = new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(p + 12)));
                        int rp = Port((uint)Marshal.ReadInt32(p + 16));
                        int pid = Marshal.ReadInt32(p + 20);
                        list.Add(Tcp(state, la, lp, ra, rp, pid));
                        p += 24;
                    }
                    else
                    {
                        // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
                        var la = new IPAddress(Bytes(p, 16));
                        int lp = Port((uint)Marshal.ReadInt32(p + 20));
                        var ra = new IPAddress(Bytes(p + 24, 16));
                        int rp = Port((uint)Marshal.ReadInt32(p + 44));
                        uint state = (uint)Marshal.ReadInt32(p + 48);
                        int pid = Marshal.ReadInt32(p + 52);
                        list.Add(Tcp(state, la, lp, ra, rp, pid));
                        p += 56;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static TableConnection Tcp(uint state, IPAddress la, int lp, IPAddress ra, int rp, int pid) => new TableConnection
        {
            Proto = FlowProto.Tcp,
            Local = new NetEndpoint(la, lp),
            Remote = state == MIB_TCP_STATE_LISTEN ? null : new NetEndpoint(ra, rp),
            Listening = state == MIB_TCP_STATE_LISTEN,
            Pid = pid,
        };

        private static void ReadUdp(int af, List<TableConnection> list)
        {
            var buf = Fetch(GetExtendedUdpTable, af, UDP_TABLE_OWNER_PID);
            if (buf == IntPtr.Zero) return;
            try
            {
                int n = Marshal.ReadInt32(buf);
                var p = buf + 4;
                for (int i = 0; i < n; i++)
                {
                    if (af == AF_INET)
                    {
                        // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid
                        var la = new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(p)));
                        int lp = Port((uint)Marshal.ReadInt32(p + 4));
                        int pid = Marshal.ReadInt32(p + 8);
                        list.Add(new TableConnection { Proto = FlowProto.Udp, Local = new NetEndpoint(la, lp), Pid = pid });
                        p += 12;
                    }
                    else
                    {
                        // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, pid
                        var la = new IPAddress(Bytes(p, 16));
                        int lp = Port((uint)Marshal.ReadInt32(p + 20));
                        int pid = Marshal.ReadInt32(p + 24);
                        list.Add(new TableConnection { Proto = FlowProto.Udp, Local = new NetEndpoint(la, lp), Pid = pid });
                        p += 28;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static byte[] Bytes(IntPtr p, int n)
        {
            var b = new byte[n];
            Marshal.Copy(p, b, 0, n);
            return b;
        }

        // ---- Processes ------------------------------------------------------------------

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr h);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public static string ImagePath(int pid)
        {
            var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
            }
            finally { CloseHandle(h); }
        }

        public static List<ProcessSnapshotEntry> Processes()
        {
            var list = new List<ProcessSnapshotEntry>();
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var e = new ProcessSnapshotEntry { Pid = p.Id, Name = p.Id == 0 ? "Idle" : p.Id == 4 ? "System" : p.ProcessName + ".exe" };
                    try { e.Start = p.StartTime; } catch { }
                    if (p.Id > 4) e.Path = ImagePath(p.Id);
                    if (e.Path != null) e.Name = System.IO.Path.GetFileName(e.Path);
                    list.Add(e);
                }
                catch { }
                finally { p.Dispose(); }
            }
            return list;
        }

        // ---- Services (which svchost runs what) -----------------------------------------

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machine, string db, uint access);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool EnumServicesStatusEx(IntPtr scm, int infoLevel, uint serviceType, uint state, IntPtr buf,
            int bufSize, out int needed, out int returned, ref int resume, string group);

        [DllImport("advapi32.dll")]
        private static extern bool CloseServiceHandle(IntPtr h);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ENUM_SERVICE_STATUS_PROCESS
        {
            public IntPtr ServiceName;
            public IntPtr DisplayName;
            public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
        }

        /// <summary>PID → service names, for running services hosted in a process.</summary>
        public static Dictionary<int, List<string>> ServicesByPid()
        {
            var map = new Dictionary<int, List<string>>();
            var scm = OpenSCManager(null, null, 0x0004 /* SC_MANAGER_ENUMERATE_SERVICE */);
            if (scm == IntPtr.Zero) return map;
            try
            {
                int resume = 0;
                EnumServicesStatusEx(scm, 0, 0x30 /* SERVICE_WIN32 */, 1 /* ACTIVE */, IntPtr.Zero, 0, out int needed, out _, ref resume, null);
                if (needed == 0) return map;
                var buf = Marshal.AllocHGlobal(needed);
                try
                {
                    resume = 0;
                    if (!EnumServicesStatusEx(scm, 0, 0x30, 1, buf, needed, out _, out int count, ref resume, null)) return map;
                    int stride = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS));
                    for (int i = 0; i < count; i++)
                    {
                        var s = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(buf + i * stride, typeof(ENUM_SERVICE_STATUS_PROCESS));
                        if (s.ProcessId == 0) continue;
                        var name = Marshal.PtrToStringUni(s.ServiceName);
                        if (!map.TryGetValue((int)s.ProcessId, out var l)) map[(int)s.ProcessId] = l = new List<string>();
                        l.Add(name);
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { CloseServiceHandle(scm); }
            return map;
        }

        // ---- Local addresses ------------------------------------------------------------

        public static IEnumerable<IPAddress> LocalAddresses()
        {
            NetworkInterface[] nics;
            try { nics = NetworkInterface.GetAllNetworkInterfaces(); }
            catch { yield break; }
            foreach (var n in nics)
            {
                UnicastIPAddressInformationCollection addrs;
                try { addrs = n.GetIPProperties().UnicastAddresses; }
                catch { continue; }
                foreach (var a in addrs) yield return NetEndpoint.Normalize(a.Address);
            }
        }
    }
}
