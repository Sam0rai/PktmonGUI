using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using PktmonGUI.ViewModels;

namespace PktmonGUI
{
    public partial class MainWindow : Window
    {
        private bool _shutdownDone;

        public MainWindow()
        {
            InitializeComponent();
            StateChanged += (s, e) => OnWindowStateChanged();
            Loaded += (s, e) => RestorePlacement();
        }

        private MainViewModel Vm => DataContext as MainViewModel;

        private void RestorePlacement()
        {
            var st = App.Services?.Settings;
            if (st == null) return;
            var area = SystemParameters.WorkArea;
            if (st.WindowWidth is double w && w >= MinWidth && w <= area.Width) Width = w;
            if (st.WindowHeight is double h && h >= MinHeight && h <= area.Height) Height = h;
            Left = area.Left + (area.Width - Width) / 2;
            Top = area.Top + (area.Height - Height) / 2;
            if (st.WindowMaximized) WindowState = WindowState.Maximized;
        }

        internal void RememberPlacement()
        {
            var st = Vm?.Services.Settings;
            if (st == null) return;
            st.WindowMaximized = WindowState == WindowState.Maximized;
            if (WindowState == WindowState.Normal) { st.WindowWidth = Width; st.WindowHeight = Height; }
        }

        private void OnWindowStateChanged()
        {
            // A maximized WindowChrome window overhangs the screen by the resize border; pad it back in.
            Root.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
            Root.BorderThickness = WindowState == WindowState.Maximized ? new Thickness(0) : new Thickness(1);
            MaxIcon.Data = (Geometry)FindResource(WindowState == WindowState.Maximized ? "I.Restore" : "I.Max");
        }

        private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void Maximize_Click(object sender, RoutedEventArgs e) =>
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        protected override async void OnClosing(CancelEventArgs e)
        {
            base.OnClosing(e);
            if (_shutdownDone || Vm == null) return;

            RememberPlacement();

            // Always stop pktmon and put foreign filters back before the process ends.
            e.Cancel = true;
            try { await Vm.ShutdownAsync(); }
            catch (Exception ex) { App.WriteCrashLog(ex); }
            _shutdownDone = true;
            Close();
        }
    }
}
