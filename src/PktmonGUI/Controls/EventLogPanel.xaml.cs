using System;
using System.Collections;
using System.Collections.Specialized;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using PktmonGUI.ViewModels;

namespace PktmonGUI.Controls
{
    /// <summary>
    /// The events an extra ETW provider produced during a capture (<c>pktmon --trace -p</c>), newest
    /// last and on the same clock as the packet grid, so a drop in the grid can be read against the
    /// stack's own reason for it. Items are <see cref="Model.EtwEventRecord"/>.
    /// </summary>
    public partial class EventLogPanel : UserControl
    {
        public EventLogPanel() { InitializeComponent(); }

        public static readonly DependencyProperty ItemsSourceProperty = DependencyProperty.Register(
            nameof(ItemsSource), typeof(IEnumerable), typeof(EventLogPanel), new PropertyMetadata(null, OnItemsSourceChanged));
        public IEnumerable ItemsSource { get => (IEnumerable)GetValue(ItemsSourceProperty); set => SetValue(ItemsSourceProperty, value); }

        public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(
            nameof(Title), typeof(string), typeof(EventLogPanel), new PropertyMetadata("ETW provider events"));
        public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }

        /// <summary>Right of the title: how many events there are.</summary>
        public static readonly DependencyProperty CountProperty = DependencyProperty.Register(
            nameof(Count), typeof(string), typeof(EventLogPanel), new PropertyMetadata(null));
        public string Count { get => (string)GetValue(CountProperty); set => SetValue(CountProperty, value); }

        /// <summary>Keep the newest event in view while a capture runs.</summary>
        public static readonly DependencyProperty FollowProperty = DependencyProperty.Register(
            nameof(Follow), typeof(bool), typeof(EventLogPanel), new PropertyMetadata(false));
        public bool Follow { get => (bool)GetValue(FollowProperty); set => SetValue(FollowProperty, value); }

        private static void OnItemsSourceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var panel = (EventLogPanel)d;
            if (e.OldValue is INotifyCollectionChanged o) o.CollectionChanged -= panel.OnItemsChanged;
            if (e.NewValue is INotifyCollectionChanged n) n.CollectionChanged += panel.OnItemsChanged;
        }

        private void OnItemsChanged(object sender, NotifyCollectionChangedEventArgs e)
        {
            // Batches past the ring buffer's threshold arrive as a Reset, so follow those too.
            if (Follow && (e.Action == NotifyCollectionChangedAction.Add || e.Action == NotifyCollectionChangedAction.Reset))
                Dispatcher.BeginInvoke(new Action(() => Scroller.ScrollToEnd()), System.Windows.Threading.DispatcherPriority.Background);
        }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            if (ItemsSource == null) return;
            Ui.CopyText(string.Join(Environment.NewLine,
                ItemsSource.Cast<Model.EtwEventRecord>().Select(i => i.Raw)));
        }
    }
}
