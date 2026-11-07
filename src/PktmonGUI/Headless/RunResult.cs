using System;
using System.Collections.Generic;
using System.Text.Encodings.Web;
using System.Text.Json;
using PktmonGUI.Attribution;
using PktmonGUI.Pcap;
using PktmonGUI.Util;

namespace PktmonGUI.Headless
{
    /// <summary>result.json: what a headless capture did. Also kept in headless.json as the last result.</summary>
    public sealed class RunResult
    {
        /// <summary>Starting, Running, Finished, Failed, Interrupted, Crashed.</summary>
        public string Status { get; set; }
        public int? ExitCode { get; set; }
        public string Meaning { get; set; }

        public string Host { get; set; }
        public string User { get; set; }
        public string Version { get; set; }
        public string CommandLine { get; set; }
        public int Pid { get; set; }

        public DateTimeOffset Started { get; set; }
        public DateTimeOffset? Stopped { get; set; }
        public string StopReason { get; set; }

        public string RunFolder { get; set; }
        public string Zip { get; set; }
        public long? ZipBytes { get; set; }
        public string ZipSha256 { get; set; }
        public string CollectedTo { get; set; }

        public SettingsInfo Settings { get; set; }
        public CaptureInfo Capture { get; set; }
        public FiltersInfo Filters { get; set; }
        public CountsInfo Counts { get; set; }
        public List<string> Files { get; set; } = new List<string>();
        public List<string> Warnings { get; set; } = new List<string>();
        public List<string> Errors { get; set; } = new List<string>();

        /// <summary>The settings.json beside the exe that gave this capture's defaults, and the flags it gave.</summary>
        public sealed class SettingsInfo
        {
            public string File { get; set; }
            public List<string> Applied { get; set; } = new List<string>();
        }

        public sealed class CaptureInfo
        {
            public string StartCommand { get; set; }
            public bool AllNics { get; set; }
            public List<string> Components { get; set; } = new List<string>();
            public int? PacketSize { get; set; }
            public int? FileSizeMb { get; set; }
            public string LogMode { get; set; }
            public string Type { get; set; }
            public bool Attribution { get; set; }
            public string Duration { get; set; }
        }

        public sealed class FiltersInfo
        {
            /// <summary>none, applied, replaced-foreign, cleared-foreign, kept.</summary>
            public string Mode { get; set; }
            public List<string> Rules { get; set; } = new List<string>();
            public int ForeignCount { get; set; }
            public string ForeignOwner { get; set; }
            public string Snapshot { get; set; }
            public bool? Restored { get; set; }
            public string RestoreAction { get; set; }
            public List<string> RestoreFailures { get; set; }
        }

        public sealed class CountsInfo
        {
            public long? PacketsTotal { get; set; }
            public long? Drops { get; set; }
            public CommentResult Comments { get; set; }
            public AttributionStats Attribution { get; set; }
        }
    }

    internal static class HeadlessJson
    {
        /// <summary>
        /// For --json on stdout: everything outside ASCII is escaped, so the output reads the same
        /// whatever code page the caller decodes it with.
        /// </summary>
        public static readonly JsonSerializerOptions Ascii = new JsonSerializerOptions(Json.Options) { Encoder = JavaScriptEncoder.Default };

        public static string ToAscii<T>(T value) => JsonSerializer.Serialize(value, Ascii);
    }
}
