using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PktmonGUI.Model;
using PktmonGUI.Parsing;
using PktmonGUI.Pktmon;

namespace PktmonGUI.Services
{
    /// <summary>
    /// Polls <c>pktmon counters --json</c> on our own timer instead of <c>--live</c>, which
    /// redraws a console and can't be parsed. Only the first poll is written to the
    /// command log; after that it would drown everything else.
    /// </summary>
    public sealed class CountersPoller : IDisposable
    {
        private readonly PktmonRunner _runner;
        private CancellationTokenSource _cts;
        private int _intervalSeconds = 1;
        private bool _loggedOnce;

        public CountersPoller(PktmonRunner runner) { _runner = runner; }

        public int IntervalSeconds
        {
            get => _intervalSeconds;
            set => _intervalSeconds = Math.Max(1, Math.Min(60, value));
        }

        public bool IsRunning => _cts != null;

        public DateTime? LastUpdate { get; private set; }

        /// <summary>Raised on a background thread with each fresh set of counters.</summary>
        public event EventHandler<IReadOnlyList<CounterRow>> Updated;
        public event EventHandler<string> Failed;

        public static PktmonCommand Command => PktmonCommand.Counters(json: true, zero: true);

        public void Start()
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            _loggedOnce = false;
            var token = _cts.Token;
            Task.Run(() => Loop(token));
        }

        public void Stop()
        {
            _cts?.Cancel();
            _cts = null;
        }

        /// <summary>One poll now, outside the timer (e.g. after "Reset to zero").</summary>
        public Task PollNowAsync() => PollAsync(CancellationToken.None);

        private async Task Loop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                var started = DateTime.UtcNow;
                await PollAsync(ct).ConfigureAwait(false);
                var wait = TimeSpan.FromSeconds(IntervalSeconds) - (DateTime.UtcNow - started);
                try { if (wait > TimeSpan.Zero) await Task.Delay(wait, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
        }

        private async Task PollAsync(CancellationToken ct)
        {
            try
            {
                var r = await _runner.RunAsync(Command, log: !_loggedOnce, ct: ct, timeout: TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                _loggedOnce = true;
                if (ct.IsCancellationRequested) return;
                if (!r.Success)
                {
                    Failed?.Invoke(this, r.Output.Trim());
                    return;
                }
                var rows = CountersParser.Parse(r.StdOut);
                LastUpdate = DateTime.Now;
                Updated?.Invoke(this, rows);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Failed?.Invoke(this, ex.Message); }
        }

        public void Dispose() => Stop();
    }
}
