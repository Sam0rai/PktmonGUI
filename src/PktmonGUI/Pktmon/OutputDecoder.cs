using System;
using System.IO;
using System.Text;
using System.Threading;

namespace PktmonGUI.Pktmon
{
    /// <summary>
    /// pktmon mixes encodings when its output is redirected: <c>start</c>/<c>stop</c> and the
    /// etl2txt output files are UTF-16LE with a BOM, while <c>status</c>, <c>list</c>,
    /// <c>counters</c> and real-time packet lines use the OEM code page. The encoding is
    /// therefore detected from the bytes of each stream rather than assumed.
    /// </summary>
    internal static class OutputDecoder
    {
        public static Encoding Oem
        {
            get
            {
                try { return Encoding.GetEncoding(NativeMethods.GetOEMCP()); }
                catch { return Encoding.Default; }
            }
        }

        /// <summary>Detects UTF-16LE (BOM, or NULs in odd positions) or UTF-8 BOM; otherwise OEM.</summary>
        public static Encoding Detect(byte[] b, int count, out int bomLength)
        {
            bomLength = 0;
            if (count >= 2 && b[0] == 0xFF && b[1] == 0xFE) { bomLength = 2; return Encoding.Unicode; }
            if (count >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) { bomLength = 3; return Encoding.UTF8; }
            if (count >= 4)
            {
                int oddZeros = 0, pairs = Math.Min(count / 2, 64);
                for (int i = 0; i < pairs; i++)
                    if (b[i * 2 + 1] == 0 && b[i * 2] != 0) oddZeros++;
                if (oddZeros > pairs * 3 / 4) return Encoding.Unicode;
            }
            return Oem;
        }

        public static string Decode(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return "";
            var enc = Detect(bytes, bytes.Length, out int bom);
            return enc.GetString(bytes, bom, bytes.Length - bom);
        }

        /// <summary>Reads a text file that pktmon wrote (etl2txt output), whatever its encoding.</summary>
        public static string ReadFile(string path) => Decode(File.ReadAllBytes(path));

        /// <summary>Line reader for a file pktmon wrote, for large etl2txt output.</summary>
        public static StreamReader OpenFile(string path)
        {
            var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 16);
            var head = new byte[128];
            int n = fs.Read(head, 0, head.Length);
            fs.Position = 0;
            var enc = Detect(head, n, out _);
            return new StreamReader(fs, enc, detectEncodingFromByteOrderMarks: true);
        }

        /// <summary>
        /// Reads a live stream on a background thread, detecting the encoding from the first
        /// bytes, and raises <paramref name="onLine"/> per line (CR/LF stripped).
        /// </summary>
        public static Thread PumpLines(Stream stream, Action<string> onLine, Action onEnd)
        {
            var t = new Thread(() =>
            {
                var buf = new byte[16384];
                var chars = new char[16384 * 2];
                var line = new StringBuilder();
                Decoder decoder = null;
                try
                {
                    int n;
                    while ((n = stream.Read(buf, 0, buf.Length)) > 0)
                    {
                        int offset = 0;
                        if (decoder == null)
                        {
                            var enc = Detect(buf, n, out int bom);
                            decoder = enc.GetDecoder();
                            offset = bom;
                        }
                        int c = decoder.GetChars(buf, offset, n - offset, chars, 0);
                        for (int i = 0; i < c; i++)
                        {
                            char ch = chars[i];
                            if (ch == '\n')
                            {
                                if (line.Length > 0 && line[line.Length - 1] == '\r') line.Length--;
                                onLine(line.ToString());
                                line.Clear();
                            }
                            else if (ch != '﻿') line.Append(ch);
                        }
                    }
                }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
                finally
                {
                    if (line.Length > 0) { try { onLine(line.ToString().TrimEnd('\r')); } catch { } }
                    onEnd?.Invoke();
                }
            })
            { IsBackground = true, Name = "pktmon output" };
            t.Start();
            return t;
        }
    }
}
