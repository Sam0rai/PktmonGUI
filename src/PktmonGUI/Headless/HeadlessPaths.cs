using System;
using System.IO;
using System.Linq;
using System.Text;
using PktmonGUI.Services;

namespace PktmonGUI.Headless
{
    /// <summary>
    /// Where headless mode keeps its state: %ProgramData%\PktmonGUI. It's the same folder for SYSTEM,
    /// every admin and WinRM sessions (so --stop finds a capture a SYSTEM task started), and it's
    /// local even when the exe runs from a share.
    /// </summary>
    public static class HeadlessPaths
    {
        public static string DataFolder => AppServices.ProgramDataFolder;

        public static string StatePath => Path.Combine(DataFolder, "headless.json");
        public const string SettingsFileName = "cli-settings.json";
        public static string RunsFolder => Path.Combine(DataFolder, "runs");
        public static string BinFolder => Path.Combine(DataFolder, "bin");
        public static string CliLog => Path.Combine(DataFolder, "cli.log");

        /// <summary>A computer name safe in a file name: letters, digits, '-' and '_'.</summary>
        public static string SanitizeHost(string host)
        {
            var sb = new StringBuilder();
            foreach (var c in (host ?? "").Trim())
                sb.Append(char.IsLetterOrDigit(c) && c < 128 || c == '-' || c == '_' ? c : '_');
            var s = sb.ToString().Trim('_');
            return s.Length == 0 ? "HOST" : s;
        }

        /// <summary>"SRV01-20260928-153000".</summary>
        public static string RunName(string host, DateTime localStart) =>
            SanitizeHost(host) + "-" + localStart.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);

        /// <summary>
        /// &lt;out&gt;\&lt;HOST&gt;-&lt;yyyyMMdd-HHmmss&gt;, with -2, -3… if that folder or its zip already exists.
        /// Nothing is created.
        /// </summary>
        public static string NewRunFolder(string outDir, string host, DateTime localStart, Func<string, bool> taken = null)
        {
            taken = taken ?? (p => Directory.Exists(p) || File.Exists(ZipPathFor(p)));
            var baseName = RunName(host, localStart);
            var path = Path.Combine(outDir, baseName);
            for (int n = 2; taken(path); n++) path = Path.Combine(outDir, baseName + "-" + n);
            return path;
        }

        /// <summary>The zip sits beside its run folder, never inside it.</summary>
        public static string ZipPathFor(string runFolder) => runFolder.TrimEnd('\\', '/') + ".zip";

        /// <summary>
        /// --out must be a local folder: pktmon (ETW) can't log to a share, and pktmon must not
        /// run in the Windows folder. Returns why not, or null.
        /// </summary>
        public static string ValidateOut(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "is empty";
            if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
                return "must be a local folder: pktmon can't record to a share (use --collect to copy the result there)";
            if (!(path.Length >= 3 && char.IsLetter(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')))
                return "must be a full path such as D:\\captures";
            if (!AppServices.IsSafeWorkingFolder(path)) return "must be outside the Windows folder";
            return null;
        }

        /// <summary>At run time: the drive must be a fixed or removable disk (not a mapped network drive).</summary>
        public static string CheckLocalDrive(string path)
        {
            try
            {
                var type = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(path))).DriveType;
                if (type == DriveType.Fixed || type == DriveType.Removable) return null;
                return $"{Path.GetPathRoot(path)} is a {type.ToString().ToLowerInvariant()} drive; pktmon needs a local disk";
            }
            catch (Exception ex) { return ex.Message; }
        }

        public static bool IsUnder(string path, string folder)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(folder)) return false;
            try
            {
                var p = Path.GetFullPath(path).TrimEnd('\\') + "\\";
                var f = Path.GetFullPath(folder).TrimEnd('\\') + "\\";
                return p.StartsWith(f, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>
        /// A local folder the operator named (--out, --collect, the --log file's folder), where SYSTEM
        /// writes captures. A missing one is created for SYSTEM and Administrators only. An existing one that
        /// another account could change, or a link, is refused unless <paramref name="force"/>: e.g. a new
        /// folder in the root of a drive lets every signed-in user change it. Shares are left to their
        /// owners (see the README). Returns why not, or null.
        /// </summary>
        public static string PrepareOperatorFolder(string flag, string folder, bool force)
        {
            if (string.IsNullOrEmpty(folder) || folder.StartsWith(@"\\", StringComparison.Ordinal)) return null;
            folder = folder.TrimEnd('\\', '/');
            if (!Directory.Exists(folder) && !File.Exists(folder))
            {
                try
                {
                    var parent = Path.GetDirectoryName(folder);
                    if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                }
                catch (Exception ex) { return $"{flag}: couldn't create {folder}: {ex.Message}"; }
                var error = SecureFolder.Ensure(folder, out _);
                return error == null ? null : $"{flag}: {error}";
            }
            if (force) return null;
            var problem = SecureFolder.CheckOperatorFolder(folder);
            return problem == null ? null
                : $"{flag}: {problem} SYSTEM writes captures there. Use a folder only administrators can change, or add --force.";
        }

        private static bool _dataFolderEnsured;

        /// <summary>What <see cref="EnsureDataFolder"/> set aside and why, for the command to report; null if nothing.</summary>
        public static string SetAsideNote { get; private set; }

        /// <summary>
        /// Makes sure %ProgramData%\PktmonGUI is owned by Administrators and usable by SYSTEM and
        /// Administrators only. %ProgramData% lets any user create folders, and this tool runs as SYSTEM,
        /// runs the exe in bin\ and deletes under runs\: a folder that isn't like that, or has anything
        /// unsafe in it, is renamed aside and made again (see <see cref="SecureFolder"/>). Every command
        /// calls this before it writes anything there; it does the work once per process. Returns why
        /// the folder can't be used, or null.
        /// </summary>
        public static string EnsureDataFolder()
        {
            if (_dataFolderEnsured) return null;
            var error = SecureFolder.Ensure(DataFolder, out var setAside);
            if (error != null) return error;
            _dataFolderEnsured = true;
            if (setAside != null)
            {
                SetAsideNote = setAside;
                // In the new folder's cli.log too: it's the only record once the command's output is gone.
                try { File.AppendAllText(CliLog, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] WARN  {setAside}\r\n"); } catch { }
            }
            return null;
        }
    }
}
