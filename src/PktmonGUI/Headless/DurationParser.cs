using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace PktmonGUI.Headless
{
    /// <summary>
    /// Durations on the command line: <c>90</c> (seconds), <c>90s</c>, <c>10m</c>, <c>2h</c>, <c>1h30m</c>,
    /// <c>1d</c>, <c>hh:mm:ss</c>. <c>0</c> means no limit.
    /// </summary>
    public static class DurationParser
    {
        private static readonly Regex Units = new Regex(
            @"^(?:(?<d>\d+)d)?(?:(?<h>\d+)h)?(?:(?<m>\d+)m)?(?:(?<s>\d+)s)?$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public static bool TryParse(string text, out TimeSpan value, out string error)
        {
            value = TimeSpan.Zero;
            error = null;
            var s = (text ?? "").Trim();
            if (s.Length == 0) { error = "is empty"; return false; }

            if (s.IndexOf(':') >= 0)
            {
                if (TimeSpan.TryParseExact(s, new[] { @"h\:mm\:ss", @"hh\:mm\:ss", @"d\.hh\:mm\:ss", @"m\:ss" }, CultureInfo.InvariantCulture, out value))
                    return true;
                error = $"'{text}' isn't a time: use hh:mm:ss";
                return false;
            }

            if (long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var secs))
            {
                if (secs > TimeSpan.MaxValue.TotalSeconds / 2) { error = $"'{text}' is too long"; return false; }
                value = TimeSpan.FromSeconds(secs);
                return true;
            }

            var m = Units.Match(s);
            if (!m.Success || !(m.Groups["d"].Success || m.Groups["h"].Success || m.Groups["m"].Success || m.Groups["s"].Success))
            {
                error = $"'{text}' isn't a duration: use e.g. 90s, 10m, 2h or 1h30m";
                return false;
            }
            try
            {
                value = new TimeSpan(Part(m, "d"), Part(m, "h"), Part(m, "m"), Part(m, "s"));
                return true;
            }
            catch (Exception)
            {
                error = $"'{text}' is too long";
                return false;
            }
        }

        private static int Part(Match m, string g) =>
            m.Groups[g].Success ? int.Parse(m.Groups[g].Value, CultureInfo.InvariantCulture) : 0;

        /// <summary>Compact form, e.g. "1h30m", "45s", "no limit".</summary>
        public static string Format(TimeSpan t)
        {
            if (t <= TimeSpan.Zero) return "no limit";
            var sb = new StringBuilder();
            if (t.Days > 0) sb.Append(t.Days).Append('d');
            if (t.Hours > 0) sb.Append(t.Hours).Append('h');
            if (t.Minutes > 0) sb.Append(t.Minutes).Append('m');
            if (t.Seconds > 0 || sb.Length == 0) sb.Append(t.Seconds).Append('s');
            return sb.ToString();
        }
    }
}
