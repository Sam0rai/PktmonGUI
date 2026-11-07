using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PktmonGUI.Pktmon
{
    public sealed class PktmonResult
    {
        public PktmonResult(PktmonCommand command, int exitCode, string stdout, string stderr)
        {
            Command = command;
            ExitCode = exitCode;
            StdOut = stdout ?? "";
            StdErr = stderr ?? "";
        }

        public PktmonCommand Command { get; }
        public int ExitCode { get; }
        public string StdOut { get; }
        public string StdErr { get; }
        public bool Success => ExitCode == 0;

        /// <summary>stdout and stderr together, the way a console would show them.</summary>
        public string Output => StdErr.Trim().Length == 0 ? StdOut.Trim() : (StdOut.Trim() + Environment.NewLine + StdErr.Trim()).Trim();

        public PktmonException ToException() => new PktmonException(this);
    }

    public sealed class PktmonException : Exception
    {
        public PktmonException(PktmonResult result)
            : base($"'{result.Command.DisplayText}' failed (exit {result.ExitCode}): {result.Output}")
        {
            Result = result;
        }

        public PktmonResult Result { get; }
    }

    /// <summary>
    /// Runs pktmon.exe (and other console tools such as editcap) without a console
    /// window, logging every invocation to the <see cref="CommandLog"/>.
    /// </summary>
    public sealed class PktmonRunner
    {
        private readonly CommandLog _log;

        public PktmonRunner(CommandLog log, string workingDirectory)
        {
            _log = log;
            WorkingDirectory = workingDirectory;
        }

        /// <summary>
        /// The working folder. pktmon drops PktMon.etl and temp files in its current directory,
        /// so it must never be System32.
        /// </summary>
        public string WorkingDirectory { get; set; }

        /// <summary>
        /// Answers commands instead of running them, so nothing starts a process. tools/DocShots fills the
        /// window from made-up pktmon output this way; in the app it's always null.
        /// </summary>
        internal Func<PktmonCommand, PktmonResult> Answer { get; set; }

        public static string PktmonPath =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "pktmon.exe");

        public static bool PktmonExists => File.Exists(PktmonPath);

        private string ResolveExecutable(PktmonCommand command) =>
            command.Executable == "pktmon" ? PktmonPath : command.Executable;

        private ProcessStartInfo CreateStartInfo(PktmonCommand command)
        {
            // Bytes, not text: pktmon's encoding differs per command (see OutputDecoder).
            var psi = new ProcessStartInfo(ResolveExecutable(command), command.ArgumentString)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
            };
            if (!string.IsNullOrEmpty(WorkingDirectory) && Directory.Exists(WorkingDirectory))
                psi.WorkingDirectory = WorkingDirectory;
            return psi;
        }

        /// <summary>Runs a command to completion. Never throws for a non-zero exit; check <see cref="PktmonResult.Success"/>.</summary>
        public async Task<PktmonResult> RunAsync(PktmonCommand command, bool log = true,
                                                 CancellationToken ct = default, TimeSpan? timeout = null)
        {
            var entry = log ? _log.Begin(command) : null;
            PktmonResult result;
            try
            {
                result = Answer != null ? Answer(command)
                    : await RunCoreAsync(command, ct, timeout ?? TimeSpan.FromMinutes(30)).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                entry?.Complete(new PktmonResult(command, -3, "", "Cancelled"));
                throw;
            }
            catch (Exception ex)
            {
                result = new PktmonResult(command, -1, "", ex.Message);
            }
            entry?.Complete(result);
            return result;
        }

        /// <summary>Runs a command and throws <see cref="PktmonException"/> on failure.</summary>
        public async Task<PktmonResult> RunCheckedAsync(PktmonCommand command, bool log = true, CancellationToken ct = default)
        {
            var r = await RunAsync(command, log, ct).ConfigureAwait(false);
            if (!r.Success) throw r.ToException();
            return r;
        }

        private async Task<PktmonResult> RunCoreAsync(PktmonCommand command, CancellationToken ct, TimeSpan timeout)
        {
            using (var p = new Process { StartInfo = CreateStartInfo(command) })
            {
                p.Start();
                p.StandardInput.Close();
                var stdout = new MemoryStream();
                var stderr = new MemoryStream();
                var readOut = p.StandardOutput.BaseStream.CopyToAsync(stdout);
                var readErr = p.StandardError.BaseStream.CopyToAsync(stderr);

                var exited = Task.Run(() => p.WaitForExit((int)Math.Min(int.MaxValue, timeout.TotalMilliseconds)));
                using (ct.Register(() => { try { if (!p.HasExited) p.Kill(); } catch { } }))
                {
                    bool done = await exited.ConfigureAwait(false);
                    if (!done)
                    {
                        try { p.Kill(); } catch { }
                        return new PktmonResult(command, -2, OutputDecoder.Decode(stdout.ToArray()), "Timed out after " + timeout);
                    }
                    await Task.WhenAll(readOut, readErr).ConfigureAwait(false);
                }
                ct.ThrowIfCancellationRequested();
                return new PktmonResult(command, p.ExitCode, OutputDecoder.Decode(stdout.ToArray()), OutputDecoder.Decode(stderr.ToArray()));
            }
        }

        /// <summary>
        /// Starts a long-running command (real-time capture) and raises <paramref name="onLine"/>
        /// on a background thread for every line of stdout and stderr.
        /// </summary>
        public StreamingProcess StartStreaming(PktmonCommand command, Action<string> onLine)
        {
            if (Answer != null) throw new InvalidOperationException("A real-time capture can't be answered; nothing was started.");
            var entry = _log.Begin(command);
            var p = new Process { StartInfo = CreateStartInfo(command), EnableRaisingEvents = true };
            p.Start();
            p.StandardInput.Close();
            ChildProcessGuard.Attach(p);
            var sp = new StreamingProcess(p, entry);
            sp.Start(onLine);
            return sp;
        }
    }

    /// <summary>A running pktmon process whose output is streamed.</summary>
    public sealed class StreamingProcess : IDisposable
    {
        private readonly Process _process;
        private readonly CommandLogEntry _entry;
        private readonly StringBuilder _errors = new StringBuilder();
        private readonly TaskCompletionSource<int> _exited = new TaskCompletionSource<int>();
        private int _pumpsDone;

        internal StreamingProcess(Process process, CommandLogEntry entry)
        {
            _process = process;
            _entry = entry;
        }

        internal void Start(Action<string> onLine)
        {
            OutputDecoder.PumpLines(_process.StandardOutput.BaseStream, onLine, PumpDone);
            OutputDecoder.PumpLines(_process.StandardError.BaseStream, l => { AppendError(l); onLine(l); }, PumpDone);
        }

        // Both pipes reach EOF only once the process is gone; that's when every line has been seen.
        private void PumpDone()
        {
            if (Interlocked.Increment(ref _pumpsDone) < 2) return;
            try { _process.WaitForExit(); } catch { }
            int code = SafeExitCode();
            _entry.Complete(new PktmonResult(_entry.Command, code, "", Errors));
            _exited.TrySetResult(code);
        }

        public Task<int> Exited => _exited.Task;
        public bool HasExited { get { try { return _process.HasExited; } catch { return true; } } }
        public string Errors { get { lock (_errors) return _errors.ToString(); } }

        private void AppendError(string line) { lock (_errors) _errors.AppendLine(line); }

        private int SafeExitCode() { try { return _process.ExitCode; } catch { return -1; } }

        /// <summary>Last resort when <c>pktmon stop</c> didn't end the process.</summary>
        public void Kill() { try { if (!_process.HasExited) _process.Kill(); } catch { } }

        public void Dispose() => _process.Dispose();
    }
}
