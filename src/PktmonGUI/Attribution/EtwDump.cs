using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using PktmonGUI.Util;

namespace PktmonGUI.Attribution
{
    /// <summary>
    /// <c>PktmonGUI.exe --dump-etw &lt;seconds&gt; &lt;file.json&gt;</c>: records raw Kernel-Network,
    /// Kernel-Process and DNS-Client events (field names, .NET types, raw values) plus the connection
    /// table at the same moment, as a test fixture. Comparing an event's raw ports/addresses with the
    /// table (whose byte order is documented) settles how the fields are encoded.
    /// </summary>
    public static class EtwDump
    {
        public sealed class DumpedEvent
        {
            public string Provider { get; set; }
            public int Id { get; set; }
            public string Opcode { get; set; }
            public string Time { get; set; }
            public int HeaderPid { get; set; }
            /// <summary>Template version: which fields the payload has.</summary>
            public int Version { get; set; }
            public List<DumpedField> Fields { get; set; } = new List<DumpedField>();
            /// <summary>
            /// The payload bytes (hex), for Kernel-Process events: ProcessStart's ImageName is past a
            /// SID the decoder stops at (<see cref="ProcessEventMapper"/>).
            /// </summary>
            public string Raw { get; set; }
        }

        public sealed class DumpedField
        {
            public string Name { get; set; }
            public string Type { get; set; }
            public string Value { get; set; }
        }

        public sealed class DumpedConnection
        {
            public string Proto { get; set; }
            public string Local { get; set; }
            public string Remote { get; set; }
            public int Pid { get; set; }
        }

        public sealed class Dump
        {
            public string Machine { get; set; }
            public string OsVersion { get; set; }
            public string Captured { get; set; }
            public List<DumpedEvent> Events { get; set; } = new List<DumpedEvent>();
            public List<DumpedConnection> TableBefore { get; set; } = new List<DumpedConnection>();
            public List<DumpedConnection> TableAfter { get; set; } = new List<DumpedConnection>();
            public int EventsLost { get; set; }
        }

        public static void Run(int seconds, string path, int maxPerId = 40, ulong pktMonKeywords = 0)
        {
            // Packet events are compared one-for-one with pktmon's own output, so keep more of them.
            if (pktMonKeywords != 0) maxPerId = Math.Max(maxPerId, 400);
            var dump = new Dump
            {
                Machine = "(redacted)",
                OsVersion = Environment.OSVersion.Version.ToString(),
                Captured = DateTime.Now.ToString("o", CultureInfo.InvariantCulture),
                TableBefore = Table(),
            };
            var perId = new Dictionary<string, int>();
            using (var session = new EtwAttributionSession())
            {
                session.RawEvent += e =>
                {
                    var key = e.ProviderName + "/" + (int)e.ID;
                    lock (dump)
                    {
                        perId.TryGetValue(key, out var n);
                        if (n >= maxPerId) return;
                        perId[key] = n + 1;
                        dump.Events.Add(Describe(e));
                    }
                };
                session.Start(allNetworkEvents: true, pktMonKeywords: pktMonKeywords);
                Thread.Sleep(TimeSpan.FromSeconds(Math.Max(3, seconds)));
                dump.EventsLost = session.EventsLost;
            }
            dump.TableAfter = Table();
            Json.Save(path, dump);
        }

        private static DumpedEvent Describe(TraceEvent e)
        {
            var d = new DumpedEvent
            {
                Provider = e.ProviderName,
                Id = (int)e.ID,
                Opcode = e.OpcodeName,
                Time = e.TimeStamp.ToString("o", CultureInfo.InvariantCulture),
                HeaderPid = e.ProcessID,
                Version = e.Version,
                Raw = e.ProviderGuid == EtwAttributionSession.KernelProcess ? Hex(e.EventData()) : null,
            };
            for (int i = 0; i < e.PayloadNames.Length; i++)
            {
                object v;
                try { v = e.PayloadValue(i); } catch (Exception ex) { v = "!" + ex.Message; }
                d.Fields.Add(new DumpedField
                {
                    Name = e.PayloadNames[i],
                    Type = v?.GetType().Name ?? "null",
                    Value = v is byte[] b ? Hex(b) : Convert.ToString(v, CultureInfo.InvariantCulture),
                });
            }
            return d;
        }

        private static List<DumpedConnection> Table() =>
            SystemSeeder.Connections().Where(c => !c.Listening).Select(c => new DumpedConnection
            {
                Proto = c.Proto.ToString(),
                Local = c.Local.ToString(),
                Remote = c.Remote?.ToString(),
                Pid = c.Pid,
            }).ToList();

        private static string Hex(byte[] b) => "0x" + BitConverter.ToString(b).Replace("-", "");

        private static byte[] Bytes(string hex)
        {
            if (hex.StartsWith("0x")) hex = hex.Substring(2);
            return Enumerable.Range(0, hex.Length / 2).Select(i => Convert.ToByte(hex.Substring(i * 2, 2), 16)).ToArray();
        }

        /// <summary>A dumped event's raw payload, or null if it wasn't recorded.</summary>
        public static byte[] RawOf(DumpedEvent e) => e.Raw == null ? null : Bytes(e.Raw);

        /// <summary>Rebuilds a payload lookup from a dumped event, typed the way TraceEvent delivered it.</summary>
        public static Func<string, object> FieldsOf(DumpedEvent e) => name =>
        {
            var f = e.Fields.FirstOrDefault(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase));
            if (f == null || f.Value == null) return null;
            switch (f.Type)
            {
                case "Int32": return int.Parse(f.Value, CultureInfo.InvariantCulture);
                case "UInt32": return uint.Parse(f.Value, CultureInfo.InvariantCulture);
                case "Int16": return short.Parse(f.Value, CultureInfo.InvariantCulture);
                case "UInt16": return ushort.Parse(f.Value, CultureInfo.InvariantCulture);
                case "Int64": return long.Parse(f.Value, CultureInfo.InvariantCulture);
                case "UInt64": return ulong.Parse(f.Value, CultureInfo.InvariantCulture);
                case "IPAddress": return IPAddress.Parse(f.Value);
                case "Byte[]": return Bytes(f.Value);
                default: return f.Value;
            }
        };
    }
}
