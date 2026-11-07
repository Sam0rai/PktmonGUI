using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace PktmonGUI.Util
{
    public enum AppTheme { Dark, Light, System }

    /// <summary>
    /// Swaps the palette dictionary (Themes/Dark.xaml or Themes/Light.xaml) in the application's merged
    /// resources. Views reference B.* and C.* with DynamicResource, so they repaint in place.
    /// </summary>
    public static class ThemeManager
    {
        private static readonly Dictionary<string, SolidColorBrush> Live = new Dictionary<string, SolidColorBrush>();
        private static bool _watchingSystem;

        public static AppTheme Mode { get; private set; } = AppTheme.Dark;
        /// <summary>The palette in use; for <see cref="AppTheme.System"/> it follows Windows' app mode.</summary>
        public static bool IsLight { get; private set; }

        public static event EventHandler Changed;

        public static void Apply(AppTheme mode)
        {
            Mode = mode;
            if (mode == AppTheme.System && !_watchingSystem)
            {
                _watchingSystem = true;
                SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            }
            Load(mode == AppTheme.Light || (mode == AppTheme.System && WindowsPrefersLight()));
        }

        /// <summary>
        /// A brush for code that hands out theme colors (converters). It's a local value, so the
        /// DynamicResource machinery doesn't reach it; instead its Color is updated on every switch.
        /// </summary>
        public static Brush LiveBrush(string key)
        {
            if (Live.TryGetValue(key, out var b)) return b;
            if (!(Application.Current?.TryFindResource(key) is SolidColorBrush source)) return Brushes.Gray;
            b = new SolidColorBrush(source.Color);
            Live[key] = b;
            return b;
        }

        private static void Load(bool light)
        {
            var app = Application.Current;
            if (app == null) return;
            var merged = app.Resources.MergedDictionaries;
            var index = merged.ToList().FindIndex(IsPalette);
            if (index >= 0 && light == IsLight) return;

            var name = typeof(ThemeManager).Assembly.GetName().Name;
            var palette = new ResourceDictionary
            {
                Source = new Uri($"pack://application:,,,/{name};component/Themes/{(light ? "Light" : "Dark")}.xaml")
            };
            if (index >= 0) merged[index] = palette;
            else merged.Insert(0, palette);
            IsLight = light;

            foreach (var pair in Live)
                if (palette[pair.Key] is SolidColorBrush b) pair.Value.Color = b.Color;
            Changed?.Invoke(null, EventArgs.Empty);
        }

        private static bool IsPalette(ResourceDictionary d)
        {
            var s = d.Source?.OriginalString;
            return s != null && (s.EndsWith("Themes/Dark.xaml", StringComparison.OrdinalIgnoreCase)
                              || s.EndsWith("Themes/Light.xaml", StringComparison.OrdinalIgnoreCase));
        }

        private static void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            if (e.Category != UserPreferenceCategory.General) return;
            Application.Current?.Dispatcher.BeginInvoke(new Action(() =>
            {
                if (Mode == AppTheme.System) Load(WindowsPrefersLight());
            }));
        }

        /// <summary>Settings › Personalization › Colors › "Choose your default app mode".</summary>
        private static bool WindowsPrefersLight()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                    return key?.GetValue("AppsUseLightTheme") is int v && v != 0;
            }
            catch { return false; }
        }
    }
}
