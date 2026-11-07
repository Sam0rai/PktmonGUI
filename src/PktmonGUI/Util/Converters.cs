using System;
using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using PktmonGUI.Model;

namespace PktmonGUI.Util
{
    public sealed class BoolToVisibilityConverter : IValueConverter
    {
        public bool Invert { get; set; }
        public bool Hide { get; set; }

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool b = value is bool v && v;
            if (Invert) b = !b;
            return b ? Visibility.Visible : (Hide ? Visibility.Hidden : Visibility.Collapsed);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            (value is Visibility v && v == Visibility.Visible) ^ Invert;
    }

    /// <summary>Visible when the value is non-null, a non-empty string, a non-zero number or a non-empty collection.</summary>
    public sealed class HasValueToVisibilityConverter : IValueConverter
    {
        public bool Invert { get; set; }

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool has = HasValue(value);
            if (Invert) has = !has;
            return has ? Visibility.Visible : Visibility.Collapsed;
        }

        internal static bool HasValue(object value)
        {
            switch (value)
            {
                case null: return false;
                case string s: return s.Length > 0;
                case int i: return i != 0;
                case long l: return l != 0;
                case bool b: return b;
                case ICollection c: return c.Count > 0;
                default: return true;
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    public sealed class InverseBoolConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => !(value is bool b && b);
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => !(value is bool b && b);
    }

    /// <summary>
    /// A grid column that takes its share of the room only when something is there to fill it.
    /// Collapsing the child isn't enough: a star column keeps its width whether or not it has one.
    /// <c>Width="{Binding HasEvents, Converter={StaticResource StarIfTrue}}"</c>
    /// </summary>
    public sealed class BoolToStarWidthConverter : IValueConverter
    {
        /// <summary>Star weight when true. 1 splits the room evenly with one other star column.</summary>
        public double Stars { get; set; } = 1;

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
            value is bool b && b ? new GridLength(Stars, GridUnitType.Star) : new GridLength(0);

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
    }

    /// <summary>Two-way binding of a RadioButton to an enum value: <c>IsChecked="{Binding Mode, Converter={StaticResource EnumEq}, ConverterParameter=Live}"</c>.</summary>
    public sealed class EnumEqualsConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
            value != null && parameter != null && string.Equals(value.ToString(), parameter.ToString(), StringComparison.OrdinalIgnoreCase);

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b && b && parameter != null)
            {
                var t = Nullable.GetUnderlyingType(targetType) ?? targetType;
                return t.IsEnum ? Enum.Parse(t, parameter.ToString(), true) : parameter;
            }
            return Binding.DoNothing;
        }
    }

    public sealed class NumberConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value == null) return "";
            try { return System.Convert.ToInt64(value).ToString("N0", CultureInfo.CurrentCulture); }
            catch { return value.ToString(); }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    public sealed class BytesConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value == null) return "";
            try { return Format(System.Convert.ToInt64(value)); }
            catch { return value.ToString(); }
        }

        public static string Format(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            double v = bytes / 1024.0;
            string[] units = { "KB", "MB", "GB", "TB" };
            int u = 0;
            while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
            return v.ToString(v < 10 ? "0.0" : "0", CultureInfo.CurrentCulture) + " " + units[u];
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    public sealed class ToneToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string key;
            switch (value)
            {
                case FieldTone.Good: key = "B.Good"; break;
                case FieldTone.Warn: key = "B.Warn"; break;
                case FieldTone.Bad: key = "B.Bad"; break;
                case Direction.Rx: key = "B.Rx"; break;
                case Direction.Tx: key = "B.Tx"; break;
                case CheckState.Ok: key = "B.Good"; break;
                case CheckState.Warn: key = "B.Warn"; break;
                case CheckState.Fail: key = "B.Bad"; break;
                case CheckState.Pending: key = "B.TextFaint"; break;
                default: key = "B.Text2"; break;
            }
            return ThemeManager.LiveBrush(key);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    public sealed class CheckStateToGeometryConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string key;
            switch (value)
            {
                case CheckState.Ok: key = "I.Check"; break;
                case CheckState.Warn: key = "I.Info"; break;
                case CheckState.Fail: key = "I.Cross"; break;
                default: key = "I.Info"; break;
            }
            return Application.Current.TryFindResource(key) as Geometry;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    /// <summary>Visible when the bound enum equals the parameter.</summary>
    public sealed class EnumToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
            value != null && parameter != null && string.Equals(value.ToString(), parameter.ToString(), StringComparison.OrdinalIgnoreCase)
                ? Visibility.Visible : Visibility.Collapsed;

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    public enum CheckState { Pending, Ok, Warn, Fail }
}
