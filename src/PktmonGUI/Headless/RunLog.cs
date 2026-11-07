using System;
using System.IO;
using System.Linq;
using System.Text;
using PktmonGUI.Pktmon;

namespace PktmonGUI.Headless
{
    public enum Verbosity { Normal, Quiet, Silent }

    /// <summary>
    /// run.log: every command, note, warning and error, timestamped. Each write opens, appends and
    /// closes, so the file survives a crash and never blocks zipping the run folder. Mirrors to the
    /// console by verbosity (commands and info only at Normal; nothing when Silent, e.g. --json).
    /// </summary>
    internal sealed class RunLog
    {
        private const int MaxOutputLines = 200;
        private static readonly Encoding Utf8 = new UTF8Encoding(false);

        private readonly object _lock = new object();
        private readonly string _extra;
        private readonly ConsoleOutput _console;
        private readonly Verbosity _verbosity;
        private string _path;

        public RunLog(string path, string extraPath, ConsoleOutput console, Verbosity verbosity)
        {
            _path = path;
            _extra = extraPath;
            _console = console ?? ConsoleOutput.Disabled;
            _verbosity = verbosity;
        }

        public string Path { get { lock (_lock) return _path; } }

        public void Info(string text) => Write("INFO", text, _verbosity == Verbosity.Normal ? text : null);
        public void Warn(string text) => Write("WARN", text, _verbosity != Verbosity.Silent ? "warning: " + text : null);
        public void Error(string text) => Write("ERROR", text, _verbosity != Verbosity.Silent ? "error: " + text : null);
        /// <summary>File only.</summary>
        public void Detail(string text) => Write("", text, null);
        /// <summary>The closing line: shown unless --json.</summary>
        public void Final(string text) => Write("INFO", text, _verbosity != Verbosity.Silent ? text : null);

        /// <summary>Continues in another file, e.g. cli.log once the run folder is zipped and deleted.</summary>
        public void SwitchTo(string path)
        {
            lock (_lock) _path = path;
        }

        /// <summary>Mirrors every command PktmonGUI runs (and its output) into this log.</summary>
        public void Attach(CommandLog log)
        {
            log.Added += e =>
            {
                if (e.IsNote) Info(e.Command.Note);
                else Write("CMD", "> " + e.Command.DisplayText + (e.Command.Note != null ? "    # " + e.Command.Note : ""),
                           _verbosity == Verbosity.Normal ? "> " + e.Command.DisplayText : null);
            };
            log.Completed += (e, r) =>
            {
                var lines = (r.Output ?? "").Replace("\r", "").Split('\n').Where(l => l.Trim().Length > 0).ToList();
                var sb = new StringBuilder("  exit " + r.ExitCode);
                foreach (var l in lines.Take(MaxOutputLines)) sb.Append('\n').Append("  | ").Append(l);
                if (lines.Count > MaxOutputLines) sb.Append('\n').Append($"  | … {lines.Count - MaxOutputLines} more lines");
                Write("", sb.ToString(), null);
                if (!r.Success && _verbosity != Verbosity.Silent)
                    _console.WriteLine($"  exit {r.ExitCode}: " + string.Join(" ", lines.Take(3)));
            };
        }

        private void Write(string level, string text, string consoleText)
        {
            var lines = (text ?? "").Replace("\r", "").Split('\n');
            var prefix = "[" + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + level.PadRight(5) + " ";
            var pad = new string(' ', prefix.Length);
            var sb = new StringBuilder();
            for (int i = 0; i < lines.Length; i++) sb.Append(i == 0 ? prefix : pad).Append(lines[i]).Append("\r\n");
            var block = sb.ToString();
            lock (_lock)
            {
                Append(_path, block);
                if (_extra != null) Append(_extra, block);
            }
            if (consoleText != null) _console.WriteLine(consoleText);
        }

        private static void Append(string path, string block)
        {
            if (path == null) return;
            // cli.log can be the first thing written (a usage error): nothing goes into the data folder before it's made safe.
            if (HeadlessPaths.IsUnder(path, HeadlessPaths.DataFolder) && HeadlessPaths.EnsureDataFolder() != null) return;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try { File.AppendAllText(path, block, Utf8); return; }
                catch (DirectoryNotFoundException)
                {
                    try { Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)); } catch { return; }
                }
                catch (IOException) { System.Threading.Thread.Sleep(50); }
                catch { return; }
            }
        }
    }
}
