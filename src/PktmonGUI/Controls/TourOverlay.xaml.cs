using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using PktmonGUI.Util;
using PktmonGUI.ViewModels;

namespace PktmonGUI.Controls
{
    /// <summary>
    /// The guided tour over the main window: dims everything but the current step's control (found by its
    /// <see cref="Tour"/> key) and puts the card beside it. A step whose control isn't showing gets a
    /// centred card. The spotlight follows the control through resizes, page switches and the sidebar.
    /// </summary>
    public partial class TourOverlay : UserControl
    {
        private const double Pad = 4, Gap = 12, Edge = 16;

        /// <summary>Height of the strip at the top (the title bar) left usable while the tour is open.</summary>
        public static readonly DependencyProperty OpenTopProperty =
            DependencyProperty.Register(nameof(OpenTop), typeof(double), typeof(TourOverlay), new PropertyMetadata(0.0));

        public double OpenTop
        {
            get => (double)GetValue(OpenTopProperty);
            set => SetValue(OpenTopProperty, value);
        }

        private TourViewModel _vm;
        private FrameworkElement _target;
        private Rect? _shownTarget;
        private Size _shownSize;
        private IInputElement _focusBefore;

        public TourOverlay()
        {
            InitializeComponent();
            DataContextChanged += (s, e) =>
            {
                if (_vm != null) _vm.PropertyChanged -= OnVmChanged;
                _vm = e.NewValue as TourViewModel;
                if (_vm != null) _vm.PropertyChanged += OnVmChanged;
            };
            IsVisibleChanged += (s, e) => OnShownOrHidden();
            LayoutUpdated += (s, e) => Track();
            PreviewKeyDown += OnKey;
        }

        /// <summary>The control the current step points at, as last found (null when it isn't showing).</summary>
        internal FrameworkElement Target => _target;

        private void OnShownOrHidden()
        {
            if (IsVisible)
            {
                _focusBefore = Keyboard.FocusedElement;
                Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(Refresh));
            }
            else
            {
                _target = null;
                _shownTarget = null;
                if (_focusBefore is UIElement el && el.IsVisible) el.Focus();
                _focusBefore = null;
            }
        }

        private void OnVmChanged(object sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName != nameof(TourViewModel.Index)) return;
            // The step may switch pages; find its control once that page has laid out.
            _target = null;
            Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(Refresh));
        }

        private void Refresh()
        {
            if (!IsVisible || _vm == null) return;
            _target = Tour.FindTarget(Window.GetWindow(this), _vm.Current.Key);
            Place(Bounds());
            NextButton.Focus();
        }

        /// <summary>Called after every layout pass while open: re-place only when the control moved or vanished.</summary>
        private void Track()
        {
            if (!IsVisible || _vm == null) return;
            if (_target == null || !_target.IsVisible) _target = Tour.FindTarget(Window.GetWindow(this), _vm.Current.Key);
            var bounds = Bounds();
            if (bounds != _shownTarget || RenderSize != _shownSize) Place(bounds);
        }

        /// <summary>The part of the control that's on screen: a list taller than its scroll area is cut to the visible part.</summary>
        private Rect? Bounds()
        {
            if (_target == null || !_target.IsVisible) return null;
            try
            {
                var r = _target.TransformToVisual(this).TransformBounds(new Rect(_target.RenderSize));
                for (var p = VisualTreeHelper.GetParent(_target); p != null; p = VisualTreeHelper.GetParent(p))
                    if (p is ScrollContentPresenter view)
                        r.Intersect(view.TransformToVisual(this).TransformBounds(new Rect(view.RenderSize)));
                return r.IsEmpty ? (Rect?)null : r;
            }
            catch (InvalidOperationException) { return null; } // not in this window's tree any more
        }

        /// <summary>The spotlight as last drawn, in this control's coordinates (null: centred card).</summary>
        internal Rect? Spotlight => _shownTarget;

        private void Place(Rect? target)
        {
            _shownTarget = target;
            _shownSize = RenderSize;
            double w = ActualWidth, h = ActualHeight;
            if (w <= 0 || h <= 0) return;
            var all = new Rect(0, 0, w, h);

            Canvas.SetTop(Blocker, OpenTop);
            Blocker.Width = w;
            Blocker.Height = Math.Max(0, h - OpenTop);

            Rect hole = Rect.Empty;
            if (target is Rect t)
            {
                hole = Rect.Inflate(t, Pad, Pad);
                hole.Intersect(all);
            }
            if (hole.IsEmpty)
            {
                Scrim.Data = new RectangleGeometry(all);
                Ring.Visibility = Visibility.Collapsed;
            }
            else
            {
                Scrim.Data = new CombinedGeometry(GeometryCombineMode.Exclude, new RectangleGeometry(all), new RectangleGeometry(hole, 6, 6));
                Ring.Visibility = Visibility.Visible;
                Canvas.SetLeft(Ring, hole.X);
                Canvas.SetTop(Ring, hole.Y);
                Ring.Width = hole.Width;
                Ring.Height = hole.Height;
            }

            CardBox.Measure(new Size(CardBox.Width, double.PositiveInfinity));
            var card = CardPosition(hole, CardBox.DesiredSize, w, h);
            Canvas.SetLeft(CardBox, card.X);
            Canvas.SetTop(CardBox, card.Y);
        }

        /// <summary>Below the control, else above, right or left of it; inside it, bottom right, when it fills the window.</summary>
        internal static Point CardPosition(Rect hole, Size card, double w, double h)
        {
            double Clamp(double v, double min, double max) => Math.Max(min, Math.Min(v, Math.Max(min, max)));
            double ClampX(double x) => Clamp(x, Edge, w - card.Width - Edge);
            double ClampY(double y) => Clamp(y, Edge, h - card.Height - Edge);

            if (hole.IsEmpty) return new Point(ClampX((w - card.Width) / 2), ClampY((h - card.Height) / 2));
            if (hole.Bottom + Gap + card.Height <= h - Edge) return new Point(ClampX(hole.Left), hole.Bottom + Gap);
            if (hole.Top - Gap - card.Height >= Edge) return new Point(ClampX(hole.Left), hole.Top - Gap - card.Height);
            if (hole.Right + Gap + card.Width <= w - Edge) return new Point(hole.Right + Gap, ClampY(hole.Top));
            if (hole.Left - Gap - card.Width >= Edge) return new Point(hole.Left - Gap - card.Width, ClampY(hole.Top));
            return new Point(ClampX(hole.Right - card.Width - Gap), ClampY(hole.Bottom - card.Height - Gap));
        }

        private void OnKey(object sender, KeyEventArgs e)
        {
            if (_vm == null) return;
            switch (e.Key)
            {
                case Key.Escape: _vm.CloseCommand.Execute(null); break;
                case Key.Right: _vm.NextCommand.Execute(null); break;
                case Key.Left: if (_vm.BackCommand.CanExecute(null) && !_vm.IsWelcome) _vm.BackCommand.Execute(null); break;
                default: return;
            }
            e.Handled = true;
        }

        /// <summary>A click outside the card keeps the keyboard on it, so keys never reach the page underneath.</summary>
        private void Blocker_MouseDown(object sender, MouseButtonEventArgs e)
        {
            NextButton.Focus();
            e.Handled = true;
        }
    }
}
