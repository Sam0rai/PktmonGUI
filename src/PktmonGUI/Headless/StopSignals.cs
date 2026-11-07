using System;
using System.Threading;
using System.Threading.Tasks;

namespace PktmonGUI.Headless
{
    public enum StopReason { None, Duration, StopRequested, CtrlC, ConsoleClosed, PktmonEndedExternally, LowDisk }

    /// <summary>Everything that ends a headless capture; the first one wins.</summary>
    internal sealed class StopSignals : IDisposable
    {
        private readonly TaskCompletionSource<StopReason> _stopped =
            new TaskCompletionSource<StopReason>(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private RegisteredWaitHandle _eventWait;
        private int _ctrlCPresses;
        private bool _hooked;

        // SetConsoleCtrlHandler holds a raw function pointer: the delegate must never be collected.
        private static HeadlessNative.ConsoleCtrlHandler _handler;
        private static StopSignals _active;

        public Task<StopReason> Stopped => _stopped.Task;

        /// <summary>
        /// Skip the slow work (conversion, zip): the console is closing (Windows ends the process
        /// about 5 s later) or Ctrl+C was pressed twice. Stop pktmon and restore the machine only.
        /// </summary>
        public bool FastPath { get; private set; }

        /// <summary>Set once pktmon is stopped and the filters are back; the console-close handler waits for it.</summary>
        public ManualResetEventSlim MachineRestored { get; } = new ManualResetEventSlim(false);

        public bool Trigger(StopReason reason) => _stopped.TrySetResult(reason);

        public void StartDuration(TimeSpan? duration)
        {
            if (!duration.HasValue || duration.Value <= TimeSpan.Zero) return;
            _ = DelayLongAsync(duration.Value, _cts.Token).ContinueWith(t =>
            {
                if (t.Status == TaskStatus.RanToCompletion) Trigger(StopReason.Duration);
            }, TaskScheduler.Default);
        }

        /// <summary>Task.Delay tops out at about 24.8 days; longer captures wait in steps.</summary>
        private static async Task DelayLongAsync(TimeSpan duration, CancellationToken ct)
        {
            var end = DateTime.UtcNow + duration;
            while (true)
            {
                var left = end - DateTime.UtcNow;
                if (left <= TimeSpan.Zero) return;
                await Task.Delay(left > TimeSpan.FromDays(1) ? TimeSpan.FromDays(1) : left, ct).ConfigureAwait(false);
            }
        }

        /// <summary>--stop from another process sets this event.</summary>
        public void WatchStopEvent(EventWaitHandle stopEvent)
        {
            _eventWait = ThreadPool.RegisterWaitForSingleObject(stopEvent,
                (state, timedOut) => Trigger(StopReason.StopRequested), null, Timeout.Infinite, executeOnlyOnce: true);
        }

        /// <summary>Ctrl+C, Ctrl+Break and console close, when attached to the console that started us.</summary>
        public void HookConsole()
        {
            _active = this;
            if (_handler == null) _handler = OnConsoleEvent;
            _hooked = HeadlessNative.SetConsoleCtrlHandler(_handler, true);
        }

        private static bool OnConsoleEvent(int type)
        {
            var s = _active;
            if (s == null) return false;
            switch (type)
            {
                case HeadlessNative.CTRL_C_EVENT:
                case HeadlessNative.CTRL_BREAK_EVENT:
                    if (Interlocked.Increment(ref s._ctrlCPresses) > 1) s.FastPath = true;
                    s.Trigger(StopReason.CtrlC);
                    return true;
                case HeadlessNative.CTRL_CLOSE_EVENT:
                case HeadlessNative.CTRL_SHUTDOWN_EVENT:
                    s.FastPath = true;
                    s.Trigger(StopReason.ConsoleClosed);
                    // Windows ends the process when this returns (or after about 5 s): hold it until the machine is restored.
                    s.MachineRestored.Wait(TimeSpan.FromMilliseconds(4500));
                    return true;
                default:
                    // CTRL_LOGOFF_EVENT: a user logging off isn't a reason to stop.
                    return true;
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _eventWait?.Unregister(null);
            if (_hooked) { try { HeadlessNative.SetConsoleCtrlHandler(_handler, false); } catch { } }
            if (ReferenceEquals(_active, this)) _active = null;
        }
    }
}
