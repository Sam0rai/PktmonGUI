using System;
using System.IO;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PktmonGUI.Headless
{
    /// <summary>What stdout was when the process started.</summary>
    public enum StdoutKind { None, Console, PipeOrFile }

    public enum OutputTarget { None, Handle, Console }

    public struct OutputPlan
    {
        public OutputTarget Target;
        /// <summary>Encode for the parent console's code page (else ANSI, as PowerShell decodes a console-less child).</summary>
        public bool UseConsoleCodePage;
        /// <summary>Listen for Ctrl+C / console close: only possible while attached to a console.</summary>
        public bool CtrlHandler;
    }

    /// <summary>
    /// Text output for a GUI-subsystem exe. Windows gives it no console, so: write to stdout when
    /// the caller redirected it (WinRM, SCCM, <c>| Out-Host</c>, <c>&gt; file</c>), else to the console of
    /// the process that started it (an interactive cmd or PowerShell), else nowhere (the run log is
    /// the record). Nothing ever goes to stderr: PowerShell 5.1 turns it into error records.
    /// </summary>
    internal sealed class ConsoleOutput
    {
        private readonly object _lock = new object();
        private TextWriter _writer;
        private SafeFileHandle _conout;
        private bool _needsLeadingNewline;

        public bool IsAttachedToConsole { get; private set; }
        public bool CanWrite => _writer != null || _conout != null;

        public static ConsoleOutput Disabled => new ConsoleOutput();

        /// <summary>The decision table, kept pure so it can be tested.</summary>
        public static OutputPlan Decide(StdoutKind stdout, bool parentConsoleAttached)
        {
            switch (stdout)
            {
                case StdoutKind.PipeOrFile:
                    return new OutputPlan { Target = OutputTarget.Handle, UseConsoleCodePage = parentConsoleAttached, CtrlHandler = parentConsoleAttached };
                case StdoutKind.Console:
                    return new OutputPlan { Target = OutputTarget.Console, UseConsoleCodePage = true, CtrlHandler = true };
                default:
                    return parentConsoleAttached
                        ? new OutputPlan { Target = OutputTarget.Console, UseConsoleCodePage = true, CtrlHandler = true }
                        : new OutputPlan { Target = OutputTarget.None };
            }
        }

        /// <summary>Sets up output for this process. <paramref name="enabled"/> false (a detached child) touches nothing.</summary>
        public static ConsoleOutput Create(bool enabled)
        {
            var c = new ConsoleOutput();
            if (!enabled) return c;
            try
            {
                var handle = HeadlessNative.GetStdHandle(HeadlessNative.STD_OUTPUT_HANDLE);
                var kind = Classify(handle);
                // Attach even when stdout is redirected: it brings Ctrl+C and the console's code page.
                c.IsAttachedToConsole = HeadlessNative.AttachConsole(HeadlessNative.ATTACH_PARENT_PROCESS);
                var plan = Decide(kind, c.IsAttachedToConsole);

                if (plan.Target == OutputTarget.Handle)
                {
                    var encoding = EncodingFor(plan.UseConsoleCodePage);
                    var stream = new FileStream(new SafeFileHandle(handle, ownsHandle: false), FileAccess.Write);
                    c._writer = new StreamWriter(stream, encoding) { AutoFlush = true, NewLine = "\r\n" };
                }
                else if (plan.Target == OutputTarget.Console)
                {
                    var h = HeadlessNative.CreateFileW("CONOUT$", HeadlessNative.GENERIC_READ | HeadlessNative.GENERIC_WRITE,
                        HeadlessNative.FILE_SHARE_READ | HeadlessNative.FILE_SHARE_WRITE, IntPtr.Zero, HeadlessNative.OPEN_EXISTING, 0, IntPtr.Zero);
                    if (!h.IsInvalid)
                    {
                        c._conout = h;
                        // The shell printed its prompt already (it doesn't wait for a GUI program); start on a fresh line.
                        c._needsLeadingNewline = kind == StdoutKind.None;
                    }
                }
            }
            catch { c._writer = null; c._conout = null; }
            return c;
        }

        private static StdoutKind Classify(IntPtr handle)
        {
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return StdoutKind.None;
            switch (HeadlessNative.GetFileType(handle))
            {
                case HeadlessNative.FILE_TYPE_DISK:
                case HeadlessNative.FILE_TYPE_PIPE:
                    return StdoutKind.PipeOrFile;
                case HeadlessNative.FILE_TYPE_CHAR:
                    // A console, or NUL (also a character device).
                    return HeadlessNative.GetConsoleMode(handle, out _) ? StdoutKind.Console : StdoutKind.None;
                default:
                    return StdoutKind.None;
            }
        }

        private static Encoding EncodingFor(bool consoleCodePage)
        {
            try
            {
                uint cp = consoleCodePage ? HeadlessNative.GetConsoleOutputCP() : HeadlessNative.GetACP();
                if (cp == 0) cp = HeadlessNative.GetACP();
                if (cp == 65001) return new UTF8Encoding(false);
                return Encoding.GetEncoding((int)cp);
            }
            catch { return new UTF8Encoding(false); }
        }

        public void WriteLine(string text = "")
        {
            lock (_lock)
            {
                try
                {
                    if (_writer != null) { _writer.WriteLine(text); return; }
                    if (_conout != null)
                    {
                        var s = (_needsLeadingNewline ? "\r\n" : "") + (text ?? "").Replace("\r\n", "\n").Replace("\n", "\r\n") + "\r\n";
                        _needsLeadingNewline = false;
                        HeadlessNative.WriteConsoleW(_conout, s, s.Length, out _, IntPtr.Zero);
                    }
                }
                catch
                {
                    // A closed pipe (the WinRM session went away) must never stop a capture.
                    _writer = null;
                    _conout = null;
                }
            }
        }
    }
}
