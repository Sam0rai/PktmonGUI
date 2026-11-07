using System;
using System.Collections.Generic;
using PktmonGUI.Model;

namespace PktmonGUI.Headless
{
    public enum CliAction { None, Capture, Stop, Status, Cleanup, ListAdapters, Help, Version }

    /// <summary>Everything the command line asked for, after parsing. Defaults are the documented ones.</summary>
    public sealed class HeadlessOptions
    {
        public CliAction Action { get; set; }

        /// <summary>Null: not given (until --stop; 24h for a detached capture). Zero: no limit.</summary>
        public TimeSpan? Duration { get; set; }
        /// <summary>--comp tokens, comma-split. Empty means "nics".</summary>
        public List<string> Components { get; } = new List<string>();
        /// <summary>--filter values, each as written for 'pktmon filter add'.</summary>
        public List<string> Filters { get; } = new List<string>();
        public List<string> Presets { get; } = new List<string>();
        public string FiltersFile { get; set; }
        public bool KeepFilters { get; set; }
        public int PacketSize { get; set; }
        public PacketType Type { get; set; } = PacketType.All;
        public int FileSizeMb { get; set; } = 512;
        public LogMode LogMode { get; set; } = LogMode.Circular;
        public bool NoAttribution { get; set; }
        public bool NoPcap { get; set; }
        /// <summary>--no-settings: ignore the settings.json beside the exe.</summary>
        public bool NoSettings { get; set; }
        /// <summary>The settings.json beside the exe that gave defaults, and the flags it gave.</summary>
        public string SettingsFile { get; set; }
        public List<string> SettingsApplied { get; set; } = new List<string>();

        public string Out { get; set; }
        public string Collect { get; set; }
        public bool KeepLocal { get; set; }
        public string LogFile { get; set; }

        public bool Detach { get; set; }
        public bool Force { get; set; }
        public bool Purge { get; set; }
        public TimeSpan? Timeout { get; set; }
        public bool Json { get; set; }
        public bool Quiet { get; set; }

        /// <summary>Hidden: this process is the background child a --detach parent started.</summary>
        public bool DetachedChild { get; set; }
        /// <summary>Hidden: the run folder a --detach parent picked, so it knows where results go.</summary>
        public string RunFolder { get; set; }

        /// <summary>The arguments as given, for the log and for re-launching a detached child.</summary>
        public IReadOnlyList<string> RawArgs { get; set; } = new string[0];

        /// <summary>A detached capture with no --duration stops after this, so a forgotten one can't hold the machine's filters forever.</summary>
        public static readonly TimeSpan DetachedDefaultDuration = TimeSpan.FromHours(24);

        /// <summary>The limit this capture runs with; null or zero means until stopped.</summary>
        public TimeSpan? EffectiveDuration =>
            Duration.HasValue ? (Duration.Value > TimeSpan.Zero ? Duration : null)
                              : (Detach || DetachedChild ? DetachedDefaultDuration : (TimeSpan?)null);
    }

    public sealed class CliParseResult
    {
        public HeadlessOptions Options { get; set; }
        public string Error { get; set; }
        public bool Ok => Error == null;
    }
}
