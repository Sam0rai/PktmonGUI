using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using PktmonGUI.Model;
using PktmonGUI.Parsing;
using PktmonGUI.Pktmon;

namespace PktmonGUI.Services
{
    /// <summary>
    /// Reads pktmon's components and ties them to real adapters. Component IDs are not
    /// stable across reboots, so adapters are remembered by MAC and the ID is re-read
    /// every launch.
    /// </summary>
    public sealed class ComponentResolver
    {
        private readonly PktmonRunner _runner;

        public ComponentResolver(PktmonRunner runner) { _runner = runner; }

        public List<Component> All { get; private set; } = new List<Component>();

        public IEnumerable<Component> Adapters => All.Where(c => c.IsAdapter);

        public async Task<List<Component>> LoadAsync(bool includeAll)
        {
            var r = await _runner.RunAsync(PktmonCommand.List(includeAll, includeAll, json: true)).ConfigureAwait(false);
            List<Component> list;
            var json = r.StdOut.TrimStart();
            if (r.Success && (json.StartsWith("[", StringComparison.Ordinal) || json.StartsWith("{", StringComparison.Ordinal)))
                list = ComponentListParser.Parse(r.StdOut);
            else
            {
                // Builds without --json: fall back to the text table.
                var t = await _runner.RunAsync(PktmonCommand.List(includeAll, includeAll, json: false)).ConfigureAwait(false);
                if (!t.Success) throw t.ToException();
                list = ComponentListParser.ParseText(t.StdOut);
            }

            // `list --json` implies --all and --include-hidden; mark what the plain listing would hide.
            if (!includeAll)
            {
                var adapters = list.Where(c => c.IsAdapter).ToList();
                list = adapters.Count > 0 ? adapters : list.Where(c => c.ParentId == null).ToList();
            }
            Enrich(list);
            All = list;
            return list;
        }

        internal static void Enrich(List<Component> components)
        {
            NetworkInterface[] nics;
            try { nics = NetworkInterface.GetAllNetworkInterfaces(); }
            catch { return; }

            var byMac = new Dictionary<string, NetworkInterface>(StringComparer.OrdinalIgnoreCase);
            foreach (var n in nics)
            {
                try
                {
                    var bytes = n.GetPhysicalAddress().GetAddressBytes();
                    if (bytes.Length != 6) continue;
                    var mac = string.Join("-", bytes.Select(b => b.ToString("X2")));
                    // Prefer the physical adapter over virtual ones that share its MAC.
                    if (!byMac.ContainsKey(mac) || n.OperationalStatus == OperationalStatus.Up)
                        byMac[mac] = n;
                }
                catch { }
            }

            foreach (var c in components)
            {
                if (c.MacAddress == null || !byMac.TryGetValue(c.MacAddress, out var n)) continue;
                try
                {
                    c.ConnectionName = n.Name;
                    c.InterfaceDescription = n.Description;
                    c.LinkStatus = n.OperationalStatus.ToString();
                    if (n.OperationalStatus == OperationalStatus.Up) c.LinkSpeedBps = n.Speed;
                    c.IsWireless = n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                                   (c.Name ?? "").IndexOf("Wi-Fi", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   (c.Name ?? "").IndexOf("Wireless", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   (c.Name ?? "").IndexOf("802.11", StringComparison.OrdinalIgnoreCase) >= 0;
                    var props = n.GetIPProperties();
                    c.IPv4 = props.UnicastAddresses
                        .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                        .Select(a => a.Address.ToString()).FirstOrDefault();
                }
                catch { }
            }
        }

        /// <summary>
        /// The adapters to preselect: the ones remembered by MAC, else the first connected
        /// adapter with a default gateway.
        /// </summary>
        public List<Component> PickDefaults(IEnumerable<string> rememberedMacs)
        {
            var adapters = Adapters.ToList();
            var remembered = adapters.Where(a => rememberedMacs.Contains(a.MacAddress, StringComparer.OrdinalIgnoreCase)).ToList();
            if (remembered.Count > 0) return remembered;

            string gwMac = null;
            try
            {
                var gw = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .FirstOrDefault(n => n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(System.Net.IPAddress.Any)));
                if (gw != null) gwMac = string.Join("-", gw.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));
            }
            catch { }

            var pick = adapters.FirstOrDefault(a => a.MacAddress == gwMac)
                    ?? adapters.FirstOrDefault(a => a.LinkStatus == "Up" && a.IPv4 != null && !a.IsWireless)
                    ?? adapters.FirstOrDefault(a => a.LinkStatus == "Up")
                    ?? adapters.FirstOrDefault();
            return pick == null ? new List<Component>() : new List<Component> { pick };
        }
    }
}
