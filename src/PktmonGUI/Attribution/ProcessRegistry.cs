using System;
using System.Collections.Generic;
using System.Linq;

namespace PktmonGUI.Attribution
{
    /// <summary>
    /// PID → process, over time. PIDs are recycled, so names are recorded when a process
    /// starts (Kernel-Process event or the startup snapshot) and looked up for the time of
    /// the packet, never re-resolved later against whatever holds that PID by then.
    /// </summary>
    public sealed class ProcessRegistry
    {
        public sealed class Instance
        {
            public int Pid { get; set; }
            public string Name { get; set; }
            public string Path { get; set; }
            public int? ParentPid { get; set; }
            public DateTime Start { get; set; }
            public DateTime? End { get; set; }
            public List<string> Services { get; set; } = new List<string>();
        }

        private static readonly TimeSpan EndGrace = TimeSpan.FromSeconds(5);
        private readonly Dictionary<int, List<Instance>> _byPid = new Dictionary<int, List<Instance>>();

        public IEnumerable<Instance> All => _byPid.Values.SelectMany(l => l);

        public void Seed(IEnumerable<ProcessSnapshotEntry> snapshot, IDictionary<int, List<string>> services)
        {
            foreach (var p in snapshot)
            {
                var inst = new Instance
                {
                    Pid = p.Pid,
                    Name = p.Name,
                    Path = p.Path,
                    Start = p.Start ?? FlowTable.Beginning,
                };
                if (services != null && services.TryGetValue(p.Pid, out var s)) inst.Services = s.ToList();
                Add(inst);
            }
        }

        public void Started(int pid, string imagePath, int? parentPid, DateTime time)
        {
            var path = DevicePaths.ToDosPath(imagePath);
            Add(new Instance
            {
                Pid = pid,
                Path = path,
                Name = string.IsNullOrEmpty(path) ? null : System.IO.Path.GetFileName(path),
                ParentPid = parentPid,
                Start = time,
            });
        }

        /// <summary>
        /// A process exited. ProcessStop carries the image's file name (not its path), so a process
        /// whose start event gave no path still gets its name here.
        /// </summary>
        public void Stopped(int pid, DateTime time, string imageName = null)
        {
            if (!_byPid.TryGetValue(pid, out var list))
            {
                // Started before we were watching and missed by the snapshot.
                if (!string.IsNullOrEmpty(imageName)) Add(new Instance { Pid = pid, Name = System.IO.Path.GetFileName(imageName), Start = FlowTable.Beginning, End = time });
                return;
            }
            var live = list.LastOrDefault(i => i.End == null);
            if (live == null) return;
            live.End = time;
            if (live.Name == null && !string.IsNullOrEmpty(imageName)) live.Name = System.IO.Path.GetFileName(imageName);
        }

        /// <summary>Updates the services hosted by running processes (svchost can gain services after start).</summary>
        public void UpdateServices(IDictionary<int, List<string>> services)
        {
            foreach (var kv in services)
                if (_byPid.TryGetValue(kv.Key, out var list))
                {
                    var live = list.LastOrDefault(i => i.End == null);
                    if (live != null) live.Services = kv.Value.ToList();
                }
        }

        internal void Add(Instance inst)
        {
            if (!_byPid.TryGetValue(inst.Pid, out var list)) _byPid[inst.Pid] = list = new List<Instance>(1);
            // A new start for a PID whose previous holder never reported its exit.
            var live = list.LastOrDefault(i => i.End == null);
            if (live != null && inst.Start > live.Start) live.End = inst.Start;
            list.Add(inst);
        }

        /// <summary>The process that held <paramref name="pid"/> at <paramref name="time"/>.</summary>
        public Instance Lookup(int pid, DateTime time)
        {
            if (!_byPid.TryGetValue(pid, out var list)) return null;
            Instance best = null;
            foreach (var i in list)
                if (i.Start <= time && (i.End == null || time <= i.End.Value + EndGrace) && (best == null || i.Start > best.Start))
                    best = i;
            // Clock skew at the edges: fall back to the most recent holder.
            return best ?? list.OrderByDescending(i => i.Start).First();
        }

        public bool HasLive(int pid) => _byPid.TryGetValue(pid, out var l) && l.Any(i => i.End == null);
    }

    /// <summary>Kernel-Process reports \Device\HarddiskVolumeN\... paths; map them to drive letters.</summary>
    internal static class DevicePaths
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern uint QueryDosDevice(string device, System.Text.StringBuilder target, int max);

        private static Dictionary<string, string> _map;

        public static string ToDosPath(string path)
        {
            if (string.IsNullOrEmpty(path) || !path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return path;
            var map = _map ?? (_map = Build());
            foreach (var kv in map)
                if (path.StartsWith(kv.Key + @"\", StringComparison.OrdinalIgnoreCase))
                    return kv.Value + path.Substring(kv.Key.Length);
            return path;
        }

        private static Dictionary<string, string> Build()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var drive in Environment.GetLogicalDrives())
            {
                var letter = drive.TrimEnd('\\');
                var sb = new System.Text.StringBuilder(512);
                if (QueryDosDevice(letter, sb, sb.Capacity) != 0) map[sb.ToString()] = letter;
            }
            return map;
        }
    }
}
