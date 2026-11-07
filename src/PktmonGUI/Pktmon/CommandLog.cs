using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PktmonGUI.Pktmon
{
    /// <summary>
    /// Every command PktmonGUI runs, in order. Feeds the "Commands run" panels so the
    /// user can see, copy and reproduce exactly what the GUI did to the machine.
    /// </summary>
    public sealed class CommandLog
    {
        private readonly SynchronizationContext _ui;
        private readonly object _gate = new object();

        public CommandLog(SynchronizationContext ui = null)
        {
            _ui = ui ?? SynchronizationContext.Current;
        }

        public ObservableCollection<CommandLogEntry> Entries { get; } = new ObservableCollection<CommandLogEntry>();

        /// <summary>
        /// A command started, or a note was added. Raised synchronously on the thread doing it, not the
        /// UI's; headless mode mirrors these into its run log.
        /// </summary>
        public event Action<CommandLogEntry> Added;

        /// <summary>A command finished (never raised for notes). Raised on the thread that ran it.</summary>
        public event Action<CommandLogEntry, PktmonResult> Completed;

        /// <summary>True once any command that changes machine state has run.</summary>
        public bool HasMutated => Entries.Any(e => e.IsMutating);

        internal CommandLogEntry Begin(PktmonCommand command)
        {
            var entry = new CommandLogEntry(command, _ui, this);
            Raise(() => Added?.Invoke(entry));
            Post(() => Entries.Add(entry));
            return entry;
        }

        /// <summary>Adds an informational line that isn't a command (e.g. "snapshot saved to ...").</summary>
        public void Note(string text)
        {
            var entry = new CommandLogEntry(new PktmonCommand(new string[0], text, executable: "#"), _ui, null);
            entry.Complete(new PktmonResult(entry.Command, 0, "", ""));
            Raise(() => Added?.Invoke(entry));
            Post(() => Entries.Add(entry));
        }

        internal void OnCompleted(CommandLogEntry entry, PktmonResult result) => Raise(() => Completed?.Invoke(entry, result));

        public string ToClipboardText() =>
            string.Join(Environment.NewLine, Entries.Where(e => !e.IsNote).Select(e => e.Command.DisplayText));

        private void Post(Action a)
        {
            // Without a UI thread, commands finish on pool threads; ObservableCollection isn't thread-safe.
            if (_ui == null) { lock (_gate) a(); }
            else if (SynchronizationContext.Current == _ui) a();
            else _ui.Post(_ => a(), null);
        }

        /// <summary>A listener's failure must never fail the command it's listening to.</summary>
        private static void Raise(Action a)
        {
            try { a(); } catch { }
        }
    }

    public sealed partial class CommandLogEntry : ObservableObject
    {
        private readonly SynchronizationContext _ui;
        private readonly CommandLog _owner;

        internal CommandLogEntry(PktmonCommand command, SynchronizationContext ui, CommandLog owner)
        {
            Command = command;
            _ui = ui;
            _owner = owner;
            Started = DateTime.Now;
        }

        public PktmonCommand Command { get; }
        public DateTime Started { get; }
        public string Text => IsNote ? Command.Note : Command.DisplayText;
        public string Note => IsNote ? null : Command.Note;
        public bool IsNote => Command.Executable == "#";

        public bool IsMutating
        {
            get
            {
                if (IsNote || Command.Executable != "pktmon" || Command.Args.Count == 0) return false;
                var verb = Command.Args[0];
                if (verb == "filter") return Command.Args.Count > 1 && Command.Args[1] != "list";
                return verb == "start" || verb == "stop" || verb == "reset" || verb == "unload";
            }
        }

        [ObservableProperty] private bool _isRunning = true;
        [ObservableProperty] private int? _exitCode;
        [ObservableProperty] private string _output;

        public bool Failed => ExitCode.HasValue && ExitCode.Value != 0;

        internal void Complete(PktmonResult r)
        {
            _owner?.OnCompleted(this, r);
            void Apply()
            {
                IsRunning = false;
                ExitCode = r.ExitCode;
                Output = r.Output;
                OnPropertyChanged(nameof(Failed));
            }
            if (_ui == null || SynchronizationContext.Current == _ui) Apply();
            else _ui.Post(_ => Apply(), null);
        }
    }
}
