using System;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using PktmonGUI.Views;

namespace PktmonGUI.ViewModels
{
    /// <summary>Small UI services the view models need, kept in one place.</summary>
    public static class Ui
    {
        private static Window Owner => Application.Current?.MainWindow;
        private static Dispatcher Dispatcher => Application.Current?.Dispatcher;

        /// <summary>Runs on the UI thread without blocking the caller (never Invoke: shutdown waits on the UI thread).</summary>
        public static void Post(Action a)
        {
            var d = Dispatcher;
            if (d == null) return;
            if (d.CheckAccess()) a();
            else d.BeginInvoke(a);
        }

        public static void Info(string title, string message, string detail = null) =>
            Dialog.Show(Owner, title, message, DialogButtons.Ok, DialogKind.Info, detail);

        public static void Error(string title, string message, string detail = null) =>
            Dialog.Show(Owner, title, message, DialogButtons.Ok, DialogKind.Error, detail);

        public static void Error(string title, Exception ex) =>
            Dialog.Show(Owner, title, ex.Message, DialogButtons.Ok, DialogKind.Error);

        public static bool Confirm(string title, string message, string yes = "OK", bool danger = false, string detail = null) =>
            Dialog.Show(Owner, title, message, DialogButtons.OkCancel, danger ? DialogKind.Warning : DialogKind.Question, detail, yes)
            == DialogResultKind.Ok;

        public static DialogResultKind Ask(string title, string message, string yes, string no, bool cancel = true) =>
            Dialog.Show(Owner, title, message, cancel ? DialogButtons.YesNoCancel : DialogButtons.YesNo, DialogKind.Question, null, yes, no);

        public static string Prompt(string title, string message, string initial = "") =>
            Dialog.Prompt(Owner, title, message, initial);

        public static void CopyText(string text)
        {
            // The clipboard can be briefly locked by another process (RDP clipboard sync, etc.).
            for (int i = 0; i < 5; i++)
            {
                try { Clipboard.SetDataObject(text ?? "", true); return; }
                catch (System.Runtime.InteropServices.COMException) { Thread.Sleep(60); }
            }
        }

        /// <summary>Copies the window's size into the settings, as closing it does.</summary>
        public static void RememberWindow() => (Owner as MainWindow)?.RememberPlacement();

        public static string SaveFile(string title, string filter, string fileName, string folder = null)
        {
            var d = new Microsoft.Win32.SaveFileDialog { Title = title, Filter = filter, FileName = fileName, InitialDirectory = folder ?? "" };
            return d.ShowDialog(Owner) == true ? d.FileName : null;
        }

        public static string OpenFile(string title, string filter, string folder = null)
        {
            var d = new Microsoft.Win32.OpenFileDialog { Title = title, Filter = filter, InitialDirectory = folder ?? "" };
            return d.ShowDialog(Owner) == true ? d.FileName : null;
        }

        public static string PickFolder(string description, string initial)
        {
            using (var d = new System.Windows.Forms.FolderBrowserDialog { Description = description, SelectedPath = initial ?? "", ShowNewFolderButton = true })
            {
                var owner = Owner == null ? null : new Win32Owner(new System.Windows.Interop.WindowInteropHelper(Owner).Handle);
                return d.ShowDialog(owner) == System.Windows.Forms.DialogResult.OK ? d.SelectedPath : null;
            }
        }

        public static void OpenInExplorer(string path, bool select = false)
        {
            try
            {
                if (select) System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + path + "\"");
                else System.Diagnostics.Process.Start("explorer.exe", "\"" + path + "\"");
            }
            catch (Exception ex) { Error("Couldn't open Explorer", ex); }
        }

        private sealed class Win32Owner : System.Windows.Forms.IWin32Window
        {
            public Win32Owner(IntPtr h) { Handle = h; }
            public IntPtr Handle { get; }
        }
    }
}
