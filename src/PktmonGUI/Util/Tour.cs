using System.Windows;
using System.Windows.Media;

namespace PktmonGUI.Util
{
    /// <summary>
    /// Marks a control the guided tour can point at: <c>util:Tour.Key="capture.start"</c>. The tour's
    /// steps name these keys, so the views stay free of tour logic. The user guide's screenshots
    /// (tools/DocShots) number the controls they explain by the same keys.
    /// </summary>
    public static class Tour
    {
        public static readonly DependencyProperty KeyProperty =
            DependencyProperty.RegisterAttached("Key", typeof(string), typeof(Tour), new PropertyMetadata(null));

        public static string GetKey(DependencyObject d) => (string)d.GetValue(KeyProperty);
        public static void SetKey(DependencyObject d, string value) => d.SetValue(KeyProperty, value);

        /// <summary>The first element under <paramref name="root"/> marked <paramref name="key"/> that's showing, or null.</summary>
        public static FrameworkElement FindTarget(DependencyObject root, string key)
        {
            if (root == null || string.IsNullOrEmpty(key)) return null;
            for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
            {
                var child = VisualTreeHelper.GetChild(root, i);
                if (child is FrameworkElement fe && !fe.IsVisible) continue; // nothing under a hidden element shows either
                if (child is FrameworkElement hit && GetKey(hit) == key && hit.ActualWidth > 0 && hit.ActualHeight > 0) return hit;
                var found = FindTarget(child, key);
                if (found != null) return found;
            }
            return null;
        }
    }
}
