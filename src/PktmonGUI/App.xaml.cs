using System;
using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using PktmonGUI.Services;
using PktmonGUI.Util;
using PktmonGUI.ViewModels;
using PktmonGUI.Views;

namespace PktmonGUI
{
    public partial class App : Application
    {
        public static AppServices Services { get; private set; }

        private int _crashing;

        static App()
        {
            // Explanations live in tooltips; WPF's 5 s default closes them mid-sentence.
            ToolTipService.ShowDurationProperty.OverrideMetadata(typeof(FrameworkElement), new FrameworkPropertyMetadata(30000));
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Command-line modes (headless, --dump-etw) are dispatched in Program.Main before WPF starts.
            DispatcherUnhandledException += OnDispatcherException;
            AppDomain.CurrentDomain.UnhandledException += OnDomainException;
            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, a) => { WriteCrashLog(a.Exception); a.SetObserved(); };

            Services = new AppServices(SynchronizationContext.Current);
            ThemeManager.Apply(Services.Settings.Theme);
            var vm = new MainViewModel(Services);
            var window = new MainWindow { DataContext = vm };
            MainWindow = window;
            window.Show();
            _ = vm.InitializeAsync();
        }

        private void OnDispatcherException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            WriteCrashLog(e.Exception);
            e.Handled = true;
            if (Interlocked.Exchange(ref _crashing, 1) == 1) return;
            try
            {
                Dialog.Show(MainWindow, "Something went wrong",
                    e.Exception.Message + "\n\nPktmonGUI will keep running. Details are in crash.log next to the settings.",
                    DialogButtons.Ok, DialogKind.Error);
            }
            catch { }
            finally { Interlocked.Exchange(ref _crashing, 0); }
        }

        private void OnDomainException(object sender, UnhandledExceptionEventArgs e)
        {
            WriteCrashLog(e.ExceptionObject as Exception);
            // The process is going down: stop pktmon and put foreign filters back first.
            Services?.EmergencyShutdown();
        }

        internal static void WriteCrashLog(Exception ex)
        {
            if (ex == null) return;
            try
            {
                var folder = Services?.Store.DataFolder ?? AppDomain.CurrentDomain.BaseDirectory;
                File.AppendAllText(Path.Combine(folder, "crash.log"),
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex}{Environment.NewLine}{Environment.NewLine}");
            }
            catch { }
        }
    }
}
