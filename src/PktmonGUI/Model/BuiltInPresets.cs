using System;
using System.Collections.Generic;
using System.Linq;

namespace PktmonGUI.Model
{
    /// <summary>Built-in presets from the Rickard Nobel pktmon series.</summary>
    public static class BuiltIn
    {
        private static FilterRule R(string name, string transport = null, int? port = null, TcpFlags flags = TcpFlags.None,
                                    string ether = null, string mac = null) =>
            new FilterRule { Name = name, Transport = transport, Port1 = port, TcpFlags = flags, EtherType = ether, Mac1 = mac };

        public static IReadOnlyList<Preset> Presets { get; } = new List<Preset>
        {
            new Preset { Name = "DNS", BuiltIn = true, Description = "Name resolution over UDP", Rules = { R("DNS", "UDP", 53) } },
            new Preset { Name = "RDP", BuiltIn = true, Rules = { R("RDP", "TCP", 3389) } },
            new Preset { Name = "SMB", BuiltIn = true, Rules = { R("SMB", "TCP", 445) } },
            new Preset { Name = "LDAP + Kerberos", BuiltIn = true, Rules =
                { R("LDAP", "TCP", 389), R("LDAP UDP", "UDP", 389), R("Kerberos", "TCP", 88), R("Kerberos UDP", "UDP", 88) } },
            new Preset { Name = "TCP session starts", BuiltIn = true, Description = "Every SYN: who is trying to connect where", Rules = { R("TCP SYN", "TCP", flags: TcpFlags.SYN) } },
            new Preset { Name = "TCP resets", BuiltIn = true, Rules = { R("TCP RST", "TCP", flags: TcpFlags.RST) } },
            new Preset { Name = "ICMP", BuiltIn = true, Rules = { R("ICMP", "ICMP") } },
            new Preset { Name = "CDP + LLDP", BuiltIn = true, Description = "Which switch and port am I on?", Rules = { R("CDP", mac: "01-00-0C-CC-CC-CC"), R("LLDP", ether: "0x88CC") } },
            new Preset { Name = "ARP", BuiltIn = true, Rules = { R("ARP", ether: "ARP") } },
            new Preset { Name = "DHCP", BuiltIn = true, Rules = { R("DHCP server", "UDP", 67), R("DHCP client", "UDP", 68) } },
            new Preset { Name = "HTTPS", BuiltIn = true, Rules = { R("HTTPS", "TCP", 443) } },
        };

        /// <summary>Command-line names (<c>--preset</c>) for presets whose display name doesn't make a good one.</summary>
        private static readonly Dictionary<string, string> Aliases = new Dictionary<string, string>
        {
            ["tcp-syn"] = "TCP session starts",
            ["tcp-rst"] = "TCP resets",
        };

        /// <summary>The name to type for a preset: "ldap-kerberos", "tcp-syn", "dns".</summary>
        public static string SlugOf(Preset p) =>
            Aliases.FirstOrDefault(kv => kv.Value == p.Name).Key ??
            string.Join("-", p.Name.ToLowerInvariant().Split(new[] { ' ', '+' }, StringSplitOptions.RemoveEmptyEntries));

        public static IEnumerable<string> Slugs => Presets.Select(SlugOf);

        /// <summary>
        /// Finds a built-in preset by slug or display name, ignoring case, spaces and punctuation
        /// ("LDAP + Kerberos" = "ldap-kerberos" = "ldapkerberos"). Null if there's none.
        /// </summary>
        public static Preset Find(string name)
        {
            var key = Squash(name);
            if (key.Length == 0) return null;
            foreach (var kv in Aliases)
                if (Squash(kv.Key) == key) return Presets.First(p => p.Name == kv.Value);
            return Presets.FirstOrDefault(p => Squash(p.Name) == key);
        }

        private static string Squash(string s) =>
            new string((s ?? "").Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray());
    }
}
