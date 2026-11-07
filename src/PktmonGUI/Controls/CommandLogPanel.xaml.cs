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
    /// The mockup's "Commands run" box: every command shown as it would be typed, with a note,
    /// and a Copy button. Items need Text and Note properties (CommandLogEntry or CommandPreview).
    /// </summary>
    public partial class CommandLogPanel : UserControl
    {
        public CommandLogPanel() { InitializeComponent(); }

        public static readonly DependencyProperty ItemsSourceProperty = DependencyProperty.Register(
            nameof(ItemsSource), typeof(IEnumerable), typeof(CommandLogPanel), new PropertyMetadata(null, OnItemsSourceChanged));
        public IEnumerable ItemsSource { get => (IEnumerable)GetValue(ItemsSourceProperty); set => SetValue(ItemsSourceProperty, value); }

        public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(
            nameof(Title), typeof(string), typeof(CommandLogPanel), new PropertyMetadata("Commands run"));
        public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }

        public static readonly DependencyProperty CopyTextProperty = DependencyProperty.Register(
            nameof(CopyText), typeof(string), typeof(CommandLogPanel), new PropertyMetadata("Copy"));
        public string CopyText { get => (string)GetValue(CopyTextProperty); set => SetValue(CopyTextProperty, value); }

        public static readonly DependencyProperty FooterProperty = DependencyProperty.Register(
            nameof(Footer), typeof(string), typeof(CommandLogPanel), new PropertyMetadata(null));
        public string Footer { get => (string)GetValue(FooterProperty); set => SetValue(FooterProperty, value); }

        /// <summary>Keep the newest command in view (the live session log).</summary>
        public static readonly DependencyProperty FollowProperty = DependencyProperty.Register(
            nameof(Follow), typeof(bool), typeof(CommandLogPanel), new PropertyMetadata(false));
        public bool Follow { get => (bool)GetValue(FollowProperty); set => SetValue(FollowProperty, value); }

        private static void OnItemsSourceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var panel = (CommandLogPanel)d;
            if (e.OldValue is INotifyCollectionChanged o) o.CollectionChanged -= panel.OnItemsChanged;
            if (e.NewValue is INotifyCollectionChanged n) n.CollectionChanged += panel.OnItemsChanged;
        }

        private void OnItemsChanged(object sender, NotifyCollectionChangedEventArgs e)
        {
            if (Follow && e.Action == NotifyCollectionChangedAction.Add)
                Dispatcher.BeginInvoke(new Action(() => Scroller.ScrollToEnd()), System.Windows.Threading.DispatcherPriority.Background);
        }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            if (ItemsSource == null) return;
            var lines = ItemsSource.Cast<object>()
                .Where(i => !(i is Pktmon.CommandLogEntry c && c.IsNote))
                .Select(i => (string)i.GetType().GetProperty("Text")?.GetValue(i));
            Ui.CopyText(string.Join(Environment.NewLine, lines));
        }
    }
}
