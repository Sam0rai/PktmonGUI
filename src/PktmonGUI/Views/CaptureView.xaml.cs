using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using PktmonGUI.ViewModels;

namespace PktmonGUI.Views
{
    public partial class CaptureView : UserControl
    {
        private const int WM_MOUSEHWHEEL = 0x020E;

        private CaptureViewModel _vm;
        private bool _scrollQueued;
        private ScrollViewer _gridScroller;
        private HwndSource _hwnd;
        /// <summary>Info's own width: the XAML default until the user drags its edge. It only grows past this to fill spare room.</summary>
        private double _infoWidth;
        private bool _fitQueued, _resizingInfo;

        public CaptureView()
        {
            InitializeComponent();
            DataContextChanged += (s, e) =>
            {
                if (_vm != null) { _vm.RowsAdded -= OnRowsAdded; _vm.PropertyChanged -= OnVmChanged; }
                _vm = DataContext as CaptureViewModel;
                if (_vm != null) { _vm.RowsAdded += OnRowsAdded; _vm.PropertyChanged += OnVmChanged; UpdateStartButton(); AttachColumnFilters(); }
            };

            _infoWidth = InfoColumn.Width.Value;
            // handledEventsToo: the column header marks its gripper's drag events handled.
            PacketGrid.AddHandler(ScrollViewer.ScrollChangedEvent, new ScrollChangedEventHandler(PacketGrid_ScrollChanged), true);
            PacketGrid.AddHandler(Thumb.DragStartedEvent, new DragStartedEventHandler(PacketGrid_ResizeStarted), true);
            PacketGrid.AddHandler(Thumb.DragCompletedEvent, new DragCompletedEventHandler(PacketGrid_ResizeCompleted), true);
            PacketGrid.PreviewMouseWheel += PacketGrid_PreviewMouseWheel;
            Loaded += (s, e) => HookHorizontalWheel();
            Unloaded += (s, e) => { _hwnd?.RemoveHook(WndProc); _hwnd = null; };
        }

        /// <summary>Each column's header is its filter (title + sort arrow + filter box), keyed by SortMemberPath.</summary>
        private void AttachColumnFilters()
        {
            var template = (DataTemplate)FindResource("FilterHeaderTemplate");
            foreach (var col in PacketGrid.Columns)
            {
                col.Header = _vm.FilterFor(col.SortMemberPath);
                col.HeaderTemplate = template;
                col.SortDirection = null;
            }
        }

        /// <summary>Sorting goes through typed comparers (addresses by value, sizes as numbers), not reflection.</summary>
        private void PacketGrid_Sorting(object sender, DataGridSortingEventArgs e)
        {
            e.Handled = true;
            var direction = _vm.SortBy(e.Column.SortMemberPath);
            foreach (var col in PacketGrid.Columns) col.SortDirection = null;
            e.Column.SortDirection = direction;
        }

        private void OnVmChanged(object sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(CaptureViewModel.IsRunning) || e.PropertyName == nameof(CaptureViewModel.StartText))
                UpdateStartButton();
        }

        private void UpdateStartButton()
        {
            bool running = _vm.IsRunning;
            StartIcon.Data = (Geometry)FindResource(running ? "I.Stop" : _vm.IsRecord ? "I.Record" : "I.Play");
            StartLabel.Text = running ? "Stop" : _vm.StartText;
        }

        private void OnRowsAdded(object sender, EventArgs e)
        {
            // Coalesce: one scroll per layout pass, however many batches arrived.
            if (_scrollQueued || PacketGrid.Items.Count == 0) return;
            _scrollQueued = true;
            Dispatcher.BeginInvoke(new Action(() =>
            {
                _scrollQueued = false;
                if (PacketGrid.Items.Count == 0) return;
                // Only vertical: ScrollIntoView would also jump back to the first column.
                if (GridScroller != null) GridScroller.ScrollToBottom();
                else PacketGrid.ScrollIntoView(PacketGrid.Items[PacketGrid.Items.Count - 1]);
            }), DispatcherPriority.Background);
        }

        // ---- Horizontal scrolling ------------------------------------------------------

        private ScrollViewer GridScroller => _gridScroller ?? (_gridScroller = FindScroller(PacketGrid));

        private static ScrollViewer FindScroller(DependencyObject parent)
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is ScrollViewer sv) return sv;
                var found = FindScroller(child);
                if (found != null) return found;
            }
            return null;
        }

        private void PacketGrid_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            // The header filter boxes have scroll viewers of their own; only the grid's matters.
            if (e.OriginalSource != GridScroller) return;
            if (e.ViewportWidthChange != 0 || e.ExtentWidthChange != 0) QueueFitInfo();
        }

        private void QueueFitInfo()
        {
            if (_fitQueued) return;
            _fitQueued = true;
            Dispatcher.BeginInvoke(new Action(() => { _fitQueued = false; FitInfoColumn(); }), DispatcherPriority.Render);
        }

        /// <summary>
        /// Stretches Info into whatever room the other columns leave, but never below its own
        /// width, so widening any column (or a narrow window) scrolls instead of squeezing.
        /// </summary>
        private void FitInfoColumn()
        {
            var sv = GridScroller;
            // Leave it alone while the user drags its edge, or after a double-click auto-size.
            if (sv == null || _resizingInfo || !InfoColumn.Width.IsAbsolute) return;
            double others = PacketGrid.Columns.Where(c => c != InfoColumn && c.Visibility == Visibility.Visible).Sum(c => c.ActualWidth);
            double width = Math.Max(_infoWidth, Math.Floor(sv.ViewportWidth - others));
            if (Math.Abs(InfoColumn.Width.Value - width) >= 0.5) InfoColumn.Width = new DataGridLength(width);
        }

        private bool IsInfoGripper(object source) =>
            source is Thumb t && t.TemplatedParent is DataGridColumnHeader h && h.Column == InfoColumn;

        private void PacketGrid_ResizeStarted(object sender, DragStartedEventArgs e)
        {
            if (IsInfoGripper(e.OriginalSource)) _resizingInfo = true;
        }

        private void PacketGrid_ResizeCompleted(object sender, DragCompletedEventArgs e)
        {
            if (!IsInfoGripper(e.OriginalSource)) return;
            _resizingInfo = false;
            _infoWidth = InfoColumn.ActualWidth;
            QueueFitInfo();
        }

        /// <summary>Shift+wheel scrolls sideways.</summary>
        private void PacketGrid_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (Keyboard.Modifiers != ModifierKeys.Shift || GridScroller == null) return;
            GridScroller.ScrollToHorizontalOffset(GridScroller.HorizontalOffset - e.Delta);
            e.Handled = true;
        }

        /// <summary>WPF ignores WM_MOUSEHWHEEL (tilt wheels, two-finger touchpad swipes); route it to the grid.</summary>
        private void HookHorizontalWheel()
        {
            if (_hwnd != null) return;
            _hwnd = PresentationSource.FromVisual(this) as HwndSource;
            _hwnd?.AddHook(WndProc);
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WM_MOUSEHWHEEL && IsVisible && PacketGrid.IsMouseOver && GridScroller != null)
            {
                int delta = unchecked((short)((long)wParam >> 16));
                GridScroller.ScrollToHorizontalOffset(GridScroller.HorizontalOffset + delta);
                handled = true;
            }
            return IntPtr.Zero;
        }

        private void ToggleAdvanced_Click(object sender, RoutedEventArgs e) => _vm.ShowAdvanced = !_vm.ShowAdvanced;

        private void DismissBanner_Click(object sender, RoutedEventArgs e)
        {
            _vm.Banner = null;
            _vm.BannerIsError = false;
        }
    }
}
