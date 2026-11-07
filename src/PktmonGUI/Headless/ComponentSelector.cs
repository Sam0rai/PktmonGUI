using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using PktmonGUI.Model;

namespace PktmonGUI.Headless
{
    public sealed class ComponentSelection
    {
        public bool AllNics { get; set; }
        public List<Component> Components { get; } = new List<Component>();
        public string Error { get; set; }
        public bool Ok => Error == null;

        public string Describe() =>
            AllNics ? "every network adapter (--comp nics)"
                    : string.Join(", ", Components.Select(c => $"{c.ConnectionName ?? c.Name} (id {c.Id})"));
    }

    /// <summary>
    /// Resolves --comp tokens against <c>pktmon list</c>. Component IDs change across reboots, so a
    /// remote admin more often knows an adapter's connection name, MAC or description.
    /// </summary>
    public static class ComponentSelector
    {
        public static ComponentSelection Resolve(IReadOnlyList<string> tokens, IReadOnlyList<Component> all,
                                                 Func<IReadOnlyList<Component>> pickDefault)
        {
            var sel = new ComponentSelection();
            if (tokens.Count == 0 || tokens.Count == 1 && tokens[0].Equals("nics", StringComparison.OrdinalIgnoreCase))
            {
                sel.AllNics = true;
                return sel;
            }
            var adapters = all.Where(c => c.IsAdapter).ToList();

            foreach (var token in tokens)
            {
                List<Component> found;
                if (token.Equals("nics", StringComparison.OrdinalIgnoreCase))
                    return Fail(sel, "--comp nics already means every network adapter; don't list others with it.");

                if (token.Equals("default", StringComparison.OrdinalIgnoreCase))
                {
                    found = (pickDefault?.Invoke() ?? new List<Component>()).ToList();
                    if (found.Count == 0) return Fail(sel, "--comp default: no connected adapter was found.\n" + Candidates(adapters));
                }
                else if (int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out var id))
                {
                    found = all.Where(c => c.Id == id).ToList();
                    if (found.Count == 0) return Fail(sel, $"--comp {token}: pktmon has no component with that ID (IDs change across reboots).\n" + Candidates(adapters));
                }
                else if (FilterRule.IsMac(token))
                {
                    var mac = FilterRule.NormalizeMac(token);
                    found = adapters.Where(a => string.Equals(a.MacAddress, mac, StringComparison.OrdinalIgnoreCase)).ToList();
                    if (found.Count == 0) return Fail(sel, $"--comp {token}: no adapter has that MAC.\n" + Candidates(adapters));
                }
                else if (token.IndexOfAny(new[] { '*', '?' }) >= 0)
                {
                    var rx = new Regex("^" + Regex.Escape(token).Replace(@"\*", ".*").Replace(@"\?", ".") + "$", RegexOptions.IgnoreCase);
                    found = adapters.Where(a => Names(a).Any(n => rx.IsMatch(n))).ToList();
                    if (found.Count == 0) return Fail(sel, $"--comp \"{token}\" matches no adapter.\n" + Candidates(adapters));
                }
                else
                {
                    found = adapters.Where(a => Names(a).Any(n => n.Equals(token, StringComparison.OrdinalIgnoreCase))).ToList();
                    if (found.Count == 0)
                    {
                        found = adapters.Where(a => Names(a).Any(n => n.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();
                        if (found.Count == 0) return Fail(sel, $"--comp \"{token}\" matches no adapter.\n" + Candidates(adapters));
                        if (found.Count > 1)
                            return Fail(sel, $"--comp \"{token}\" matches {found.Count} adapters; give more of the name, an ID, or use * to take them all.\n" + Candidates(found));
                    }
                }
                foreach (var c in found)
                    if (!sel.Components.Any(x => x.Id == c.Id)) sel.Components.Add(c);
            }
            return sel;
        }

        private static IEnumerable<string> Names(Component c) =>
            new[] { c.ConnectionName, c.Name, c.InterfaceDescription }.Where(n => !string.IsNullOrEmpty(n));

        private static ComponentSelection Fail(ComponentSelection sel, string error)
        {
            sel.Error = error.TrimEnd();
            return sel;
        }

        private static string Candidates(IEnumerable<Component> list)
        {
            var items = list.ToList();
            if (items.Count == 0) return "pktmon listed no network adapters.";
            return "Adapters:\n" + string.Join("\n", items.Select(a =>
                $"  {a.Id,5}  {a.ConnectionName ?? "-",-24} {a.Name}  {a.MacAddress}"));
        }
    }
}
