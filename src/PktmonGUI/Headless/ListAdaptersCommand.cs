using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PktmonGUI.Model;

namespace PktmonGUI.Headless
{
    /// <summary>--list-adapters: what --comp can select on this machine.</summary>
    internal static class ListAdaptersCommand
    {
        public static async Task<int> RunAsync(HeadlessOptions o, ConsoleOutput console)
        {
            var err = HeadlessPaths.EnsureDataFolder();
            if (err != null) return HeadlessProgram.Fail(o, console, ExitCodes.Unsupported, err);
            HeadlessProgram.WarnSetAside(o, console);
            var s = HeadlessProgram.CreateServices();
            List<Component> all;
            try { all = await s.Components.LoadAsync(includeAll: true).ConfigureAwait(false); }
            catch (Exception ex) { return HeadlessProgram.Fail(o, console, ExitCodes.Failed, "pktmon list failed: " + ex.Message); }

            var adapters = all.Where(c => c.IsAdapter).OrderByDescending(c => c.LinkStatus == "Up").ThenBy(c => c.Id).ToList();
            var defaults = new HashSet<int>(s.Components.PickDefaults(new string[0]).Select(c => c.Id));
            if (o.Json)
            {
                console.WriteLine(HeadlessJson.ToAscii(adapters.Select(a => new
                {
                    id = a.Id, connection = a.ConnectionName, name = a.Name, description = a.InterfaceDescription, mac = a.MacAddress,
                    ipv4 = a.IPv4, link = a.LinkStatus, wireless = a.IsWireless, isDefault = defaults.Contains(a.Id),
                })));
                return ExitCodes.Ok;
            }
            console.WriteLine(Table(adapters, a => defaults.Contains(a.Id)));
            console.WriteLine();
            console.WriteLine("* = what --comp default picks. The default, --comp nics, captures on every adapter.");
            console.WriteLine("--comp takes an Id (they change across reboots), a MAC, or a unique part of the connection name or description.");
            return ExitCodes.Ok;
        }

        /// <summary>A plain-text adapter table; <paramref name="mark"/> puts a '*' in the first column.</summary>
        public static string Table(IEnumerable<Component> adapters, Func<Component, bool> mark)
        {
            var rows = new List<string[]> { new[] { "", "Id", "Connection", "Name", "MAC", "IPv4", "Link", "Wi-Fi" } };
            foreach (var a in adapters)
                rows.Add(new[]
                {
                    mark(a) ? "*" : "", a.Id.ToString(), a.ConnectionName ?? "-", a.Name ?? "-", a.MacAddress ?? "-",
                    a.IPv4 ?? "-", a.LinkStatus ?? "-", a.IsWireless ? "yes" : "",
                });
            if (rows.Count == 1) return "pktmon listed no network adapters.";
            var widths = Enumerable.Range(0, rows[0].Length).Select(i => rows.Max(r => r[i].Length)).ToArray();
            var sb = new StringBuilder();
            foreach (var r in rows)
                sb.AppendLine(string.Join("  ", r.Select((cell, i) => cell.PadRight(widths[i]))).TrimEnd());
            return sb.ToString().TrimEnd();
        }
    }
}
