using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PktmonGUI
{
    /// <summary>
    /// Entry point. With no arguments it starts the GUI; with any argument it runs headless
    /// (see <see cref="Headless.HeadlessProgram"/>) without creating a WPF Application, so
    /// no window, theme or Dispatcher is ever loaded.
    /// </summary>
    /// <remarks>
    /// Each branch is its own non-inlined method: compiling <see cref="Main"/> must not pull in
    /// PresentationFramework (for the GUI) or the Costura-embedded assemblies.
    /// </remarks>
    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            HardenDllSearch();
            // Hidden fixture mode: PktmonGUI.exe --dump-etw <seconds> <file.json> [pktmonKeywordsHex] [maxPerId]
            if (args.Length >= 3 && args[0] == "--dump-etw") return RunDumpEtw(args);
            if (args.Length > 0) return RunHeadless(args, noArguments: false);
            // A service, WinRM or SCCM session has no desktop: a window would hang there unseen.
            if (!Environment.UserInteractive) return RunHeadless(args, noArguments: true);
            return RunGui();
        }

        /// <summary>
        /// Loads DLLs only from System32 (not the exe's own folder or the current directory), so a DLL
        /// planted beside the exe — which runs elevated — can't be loaded ahead of the real one. Everything
        /// PktmonGUI needs is embedded (Costura), in the GAC/framework, or in System32 (pktmon, WIC). On
        /// Windows 10 2004+ (the minimum) the flag is always available.
        /// </summary>
        private static void HardenDllSearch()
        {
            try { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32); } catch { }
        }

        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetDefaultDllDirectories(uint directoryFlags);

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int RunGui()
        {
            var app = new App();
            app.InitializeComponent();
            return app.Run();
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int RunHeadless(string[] args, bool noArguments) => Headless.HeadlessProgram.Run(args, noArguments);

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int RunDumpEtw(string[] args)
        {
            // Optional 4th argument: PktMon provider keywords in hex, e.g. 0x13 (Config | Rundown | Payload).
            ulong pktmon = args.Length >= 4 ? Convert.ToUInt64(args[3], 16) : 0;
            // Optional 5th: events kept per provider and ID (default 40).
            int maxPerId = args.Length >= 5 ? int.Parse(args[4]) : 40;
            try { Attribution.EtwDump.Run(int.Parse(args[1]), args[2], maxPerId, pktmon); }
            catch (Exception ex) { File.WriteAllText(args[2] + ".error.txt", ex.ToString()); return 1; }
            return 0;
        }
    }
}
