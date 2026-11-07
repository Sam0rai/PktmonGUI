using System.Collections.Generic;
using System.Linq;

namespace PktmonGUI.Headless
{
    /// <summary>Process exit codes of headless mode. Documented in the usage text and the README.</summary>
    public static class ExitCodes
    {
        public const int Ok = 0;
        /// <summary>pktmon or the run failed.</summary>
        public const int Failed = 1;
        /// <summary>Bad or conflicting arguments; nothing was changed.</summary>
        public const int Usage = 2;
        /// <summary>Not elevated, Windows too old, pktmon missing or denied, or not enough disk.</summary>
        public const int Unsupported = 3;
        /// <summary>Another headless capture, or another pktmon session, is running.</summary>
        public const int Busy = 4;
        /// <summary>The zip couldn't be copied to --collect; it's kept locally.</summary>
        public const int CollectFailed = 5;
        /// <summary>Finished, but something needs a look (see warnings in result.json).</summary>
        public const int Warnings = 6;
        /// <summary>--stop found nothing to stop; --status found leftovers.</summary>
        public const int NothingToStop = 7;
        /// <summary>The machine's filters or pktmon session couldn't be put back: run --cleanup.</summary>
        public const int NotRestored = 8;
        /// <summary>--stop or --detach gave up waiting; the capture process is still working.</summary>
        public const int TimedOut = 9;

        /// <summary>Most urgent first: damage to the machine's state needs action before anything else.</summary>
        private static readonly int[] Precedence =
            { Usage, Unsupported, Busy, NotRestored, Failed, TimedOut, CollectFailed, Warnings, NothingToStop, Ok };

        /// <summary>The code for a run with several outcomes, e.g. warnings plus a failed collect is 5.</summary>
        public static int Worst(IEnumerable<int> codes)
        {
            var list = codes.ToList();
            if (list.Count == 0) return Ok;
            return list.OrderBy(c => { int i = System.Array.IndexOf(Precedence, c); return i < 0 ? -1 : i; }).First();
        }

        public static string Describe(int code)
        {
            switch (code)
            {
                case Ok: return "ok";
                case Failed: return "failed";
                case Usage: return "usage error";
                case Unsupported: return "unsupported: not elevated, Windows too old, pktmon missing or denied, or not enough disk";
                case Busy: return "busy: another capture is running";
                case CollectFailed: return "collect failed; the zip is kept locally";
                case Warnings: return "done with warnings";
                case NothingToStop: return "nothing to stop, or leftovers found";
                case NotRestored: return "the machine was not fully restored: run --cleanup";
                case TimedOut: return "timed out waiting; the capture process is still working";
                default: return "exit " + code;
            }
        }

        public static IEnumerable<int> All => new[] { Ok, Failed, Usage, Unsupported, Busy, CollectFailed, Warnings, NothingToStop, NotRestored, TimedOut };
    }
}
