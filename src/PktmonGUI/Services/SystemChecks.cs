using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;

namespace PktmonGUI.Services
{
    /// <summary>Machine and process checks shared by Preflight and headless mode. No UI.</summary>
    public static class SystemChecks
    {
        /// <summary>Real-time mode, --json and the current syntax arrived with Windows 10 2004 (build 19041).</summary>
        public const int MinimumBuild = 19041;

        public static bool IsAdministrator()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        public static bool IsSystem()
        {
            try { using (var id = WindowsIdentity.GetCurrent()) return id.IsSystem; }
            catch { return false; }
        }

        /// <summary>
        /// A network logon (WinRM, PsExec without -s) carries no credentials a share would accept:
        /// the "double hop". Its token holds the NETWORK group (S-1-5-2).
        /// </summary>
        public static bool IsNetworkLogon()
        {
            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                    return id.Groups?.Any(g => g.Value == "S-1-5-2") == true;
            }
            catch { return false; }
        }

        public static string UserName()
        {
            try { using (var id = WindowsIdentity.GetCurrent()) return id.Name; }
            catch { return Environment.UserDomainName + "\\" + Environment.UserName; }
        }

        public static (string name, int build, int ubr) OsInfo()
        {
            try
            {
                using (var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                                          .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    var name = k?.GetValue("ProductName") as string ?? "Windows";
                    int.TryParse(k?.GetValue("CurrentBuildNumber") as string ?? k?.GetValue("CurrentBuild") as string, out var build);
                    int ubr = k?.GetValue("UBR") is int u ? u : 0;
                    // Windows 11 still reports "Windows 10" in ProductName.
                    if (build >= 22000 && name.StartsWith("Windows 10", StringComparison.Ordinal)) name = "Windows 11" + name.Substring(10);
                    return (name, build, ubr);
                }
            }
            catch { return ("Windows", Environment.OSVersion.Version.Build, 0); }
        }

        public static string OsText()
        {
            var os = OsInfo();
            return $"{os.name}, build {os.build}{(os.ubr > 0 ? "." + os.ubr : "")}";
        }

        /// <summary>The real-time ETW sessions PktmonGUI starts. Both outlive a process that was killed.</summary>
        public static IReadOnlyList<string> EtwSessionNames { get; } = new[]
        {
            Attribution.EtwAttributionSession.SessionName,
            Pcap.PktMonPacketTap.SessionName,
        };

        /// <summary>PktmonGUI's ETW sessions that are running now.</summary>
        public static List<string> RunningEtwSessions()
        {
            try
            {
                var active = TraceEventSession.GetActiveSessionNames();
                return EtwSessionNames.Where(n => active.Contains(n)).ToList();
            }
            catch { return new List<string>(); }
        }

        /// <summary>Stops PktmonGUI's ETW sessions left by a PktmonGUI that didn't close cleanly. Returns the ones stopped.</summary>
        public static List<string> StopLeftoverEtwSessions()
        {
            var stopped = new List<string>();
            if (Attribution.EtwAttributionSession.StopLeftover()) stopped.Add(Attribution.EtwAttributionSession.SessionName);
            if (Pcap.PktMonPacketTap.StopLeftover()) stopped.Add(Pcap.PktMonPacketTap.SessionName);
            return stopped;
        }

        /// <summary>Free bytes on the volume holding <paramref name="path"/>; null if it can't be read (e.g. UNC).</summary>
        public static long? FreeBytes(string path)
        {
            try
            {
                var root = Path.GetPathRoot(Path.GetFullPath(path));
                if (string.IsNullOrEmpty(root) || root.StartsWith(@"\\", StringComparison.Ordinal)) return null;
                return new DriveInfo(root).AvailableFreeSpace;
            }
            catch { return null; }
        }
    }
}
