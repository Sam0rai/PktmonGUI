using System.Collections.Generic;
using System.Text;

namespace PktmonGUI.Model
{
    /// <summary>
    /// Splits a command line the way CommandLineToArgvW does, the inverse of
    /// <see cref="Pktmon.PktmonCommand.QuoteArg"/>: whitespace separates arguments outside
    /// quotes, 2n backslashes before a quote are n backslashes and a quote toggle, 2n+1 are
    /// n backslashes and a literal quote, and other backslashes are literal.
    /// </summary>
    public static class ArgSplitter
    {
        public static List<string> Split(string text)
        {
            var args = new List<string>();
            if (string.IsNullOrEmpty(text)) return args;

            var cur = new StringBuilder();
            bool inQuotes = false, hasArg = false;
            int i = 0;
            while (i < text.Length)
            {
                char c = text[i];
                if (c == '\\')
                {
                    int n = 0;
                    while (i < text.Length && text[i] == '\\') { n++; i++; }
                    if (i < text.Length && text[i] == '"')
                    {
                        cur.Append('\\', n / 2);
                        if (n % 2 == 1) { cur.Append('"'); i++; }
                        // An even count leaves the quote to toggle below.
                    }
                    else cur.Append('\\', n);
                    hasArg = true;
                    continue;
                }
                if (c == '"')
                {
                    // Inside quotes, "" is a literal quote (msvcrt 2008+).
                    if (inQuotes && i + 1 < text.Length && text[i + 1] == '"') { cur.Append('"'); i += 2; }
                    else { inQuotes = !inQuotes; i++; }
                    hasArg = true;
                    continue;
                }
                if (!inQuotes && (c == ' ' || c == '\t' || c == '\r' || c == '\n'))
                {
                    if (hasArg) { args.Add(cur.ToString()); cur.Clear(); hasArg = false; }
                    i++;
                    continue;
                }
                cur.Append(c);
                hasArg = true;
                i++;
            }
            if (hasArg) args.Add(cur.ToString());
            return args;
        }
    }
}
