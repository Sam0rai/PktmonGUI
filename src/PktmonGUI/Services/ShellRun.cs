using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace PktmonGUI.Services
{
    /// <summary>
    /// Opens a file or program the way the logged-on user would, by asking the running desktop Explorer
    /// to launch it. PktmonGUI runs elevated (High integrity); a child it started itself would inherit
    /// that token, so Wireshark or a text viewer would open elevated too — against Wireshark's own advice,
    /// and a parser bug in it would then run as administrator. Explorer runs as the interactive user at
    /// Medium integrity, so a program it launches does as well.
    /// </summary>
    internal static class ShellRun
    {
        /// <summary>
        /// Launches <paramref name="file"/> (a program or a document) at Medium integrity via Explorer.
        /// Returns false if Explorer couldn't be reached (e.g. no interactive desktop); the caller then
        /// tells the user rather than falling back to an elevated launch.
        /// </summary>
        public static bool TryOpen(string file, string arguments = null, string workingDirectory = null)
        {
            bool ok = false;
            Exception failure = null;
            RunSta(() =>
            {
                try { ok = ShellExecuteViaExplorer(file, arguments, workingDirectory); }
                catch (Exception ex) { failure = ex; }
            });
            if (failure != null) throw failure;
            return ok;
        }

        private static bool ShellExecuteViaExplorer(string file, string arguments, string workingDirectory)
        {
            var shellWindows = (IShellWindows)new ShellWindows();
            try
            {
                object loc = CSIDL_DESKTOP;
                object root = null;
                var disp = shellWindows.FindWindowSW(ref loc, ref root, SWC_DESKTOP, out _, SWFO_NEEDDISPATCH);
                if (!(disp is IServiceProvider sp)) return false;

                var browserGuid = SID_STopLevelBrowser;
                var shellBrowserIid = IID_IShellBrowser;
                if (sp.QueryService(ref browserGuid, ref shellBrowserIid, out var browserObj) != 0 || !(browserObj is IShellBrowser browser))
                    return false;

                browser.QueryActiveShellView(out var view);
                try
                {
                    var dispatchIid = IID_IDispatch;
                    view.GetItemObject(SVGIO_BACKGROUND, ref dispatchIid, out var folderView);
                    // folderView is IShellFolderViewDual; its .Application is IShellDispatch2, whose ShellExecute
                    // runs in Explorer. Called late-bound through IDispatch so no Microsoft.CSharp reference is needed.
                    var shell = folderView.GetType().InvokeMember("Application", BindingFlags.GetProperty, null, folderView, null);
                    shell.GetType().InvokeMember("ShellExecute", BindingFlags.InvokeMethod, null, shell,
                        new object[] { file, arguments ?? "", workingDirectory ?? "", "open", SW_SHOWNORMAL });
                    return true;
                }
                finally { Marshal.ReleaseComObject(view); }
            }
            finally { Marshal.ReleaseComObject(shellWindows); }
        }

        /// <summary>Shell COM wants an STA thread; the WPF UI thread is one, but don't assume it.</summary>
        private static void RunSta(Action action)
        {
            if (Thread.CurrentThread.GetApartmentState() == ApartmentState.STA) { action(); return; }
            Exception error = null;
            var t = new Thread(() => { try { action(); } catch (Exception ex) { error = ex; } });
            t.SetApartmentState(ApartmentState.STA);
            t.IsBackground = true;
            t.Start();
            t.Join();
            if (error != null) throw error;
        }

        private const int CSIDL_DESKTOP = 0;
        private const int SWC_DESKTOP = 0x8;
        private const int SWFO_NEEDDISPATCH = 0x1;
        private const uint SVGIO_BACKGROUND = 0x0;
        private const int SW_SHOWNORMAL = 1;

        private static Guid SID_STopLevelBrowser = new Guid("4C96BE40-915C-11CF-99D3-00AA004AE837");
        private static Guid IID_IShellBrowser = new Guid("000214E2-0000-0000-C000-000000000046");
        private static Guid IID_IDispatch = new Guid("00020400-0000-0000-C000-000000000046");

        [ComImport, Guid("9BA05972-F6A8-11CF-A442-00A0C90A8F39")]
        private class ShellWindows { }

        [ComImport, Guid("85CB6900-4D95-11CF-960C-0080C7F4EE85"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IShellWindows
        {
            // IDispatch (4) + dispatch methods preceding FindWindowSW (8); never called, so signatures are placeholders.
            void _0(); void _1(); void _2(); void _3();
            void _4(); void _5(); void _6(); void _7(); void _8(); void _9(); void _10(); void _11();
            [return: MarshalAs(UnmanagedType.IDispatch)]
            object FindWindowSW(ref object pvarloc, ref object pvarlocRoot, int swClass, out int phwnd, int swfwOptions);
        }

        [ComImport, Guid("6d5140c1-7436-11ce-8034-00aa006009fa"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IServiceProvider
        {
            [PreserveSig]
            int QueryService(ref Guid guidService, ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object ppvObject);
        }

        [ComImport, Guid("000214E2-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IShellBrowser
        {
            // IOleWindow (2) + IShellBrowser methods before QueryActiveShellView (10); placeholders, never called.
            void _0(); void _1();
            void _2(); void _3(); void _4(); void _5(); void _6(); void _7(); void _8(); void _9(); void _10(); void _11();
            [PreserveSig]
            int QueryActiveShellView([MarshalAs(UnmanagedType.Interface)] out IShellView ppshv);
        }

        [ComImport, Guid("000214E3-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IShellView
        {
            // IOleWindow (2) + IShellView methods before GetItemObject (10); placeholders, never called.
            void _0(); void _1();
            void _2(); void _3(); void _4(); void _5(); void _6(); void _7(); void _8(); void _9(); void _10(); void _11();
            [PreserveSig]
            int GetItemObject(uint aspectOfView, ref Guid riid, [MarshalAs(UnmanagedType.IDispatch)] out object ppv);
        }
    }
}
