using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace PktmonGUI.Services
{
    public sealed class WiresharkInfo
    {
        public string Folder { get; set; }
        public string WiresharkExe { get; set; }
        public string EditcapExe { get; set; }
        public string Version { get; set; }
        public bool HasEditcap => EditcapExe != null;
    }

    /// <summary>Finds an installed (or portable) Wireshark without requiring one.</summary>
    public static class WiresharkLocator
    {
        public static WiresharkInfo Find(string extraFolder = null)
        {
            foreach (var folder in Candidates(extraFolder))
            {
                try
                {
                    if (string.IsNullOrEmpty(folder)) continue;
                    var exe = Path.Combine(folder, "Wireshark.exe");
                    if (!File.Exists(exe)) continue;
                    var editcap = Path.Combine(folder, "editcap.exe");
                    return new WiresharkInfo
                    {
                        Folder = folder,
                        WiresharkExe = exe,
                        EditcapExe = File.Exists(editcap) ? editcap : null,
                        Version = FileVersionInfo.GetVersionInfo(exe).ProductVersion?.Split(' ').FirstOrDefault(),
                    };
                }
                catch { }
            }
            return null;
        }

        private static System.Collections.Generic.IEnumerable<string> Candidates(string extra)
        {
            if (extra != null) yield return extra;
            yield return ReadRegistry(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe", "Path");
            yield return DirOf(ReadRegistry(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe", null));
            yield return DirOf(ReadRegistry(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark", "DisplayIcon"));
            yield return ReadRegistry(RegistryHive.LocalMachine, @"SOFTWARE\Wireshark", "InstallDir");
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark");
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Wireshark");
            // Not a "Wireshark" folder next to the exe: PktmonGUI runs elevated, launches Wireshark, and its
            // own folder may be writable by others; only admin-controlled install locations are trusted.
        }

        private static string DirOf(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            path = path.Trim('"').Split(',')[0];
            try { return Path.GetDirectoryName(path); } catch { return null; }
        }

        private static string ReadRegistry(RegistryHive hive, string key, string value)
        {
            try
            {
                using (var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                using (var k = root.OpenSubKey(key))
                    return k?.GetValue(value) as string;
            }
            catch { return null; }
        }
    }
}
