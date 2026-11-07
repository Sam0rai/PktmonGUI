using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PktmonGUI.Services;

namespace PktmonGUI.ViewModels
{
    /// <summary>One card of the tour: the page it shows and the control it points at (a <see cref="Util.Tour"/> key).</summary>
    public sealed class TourStep
    {
        public TourStep(Page? page, string key, string title, string text)
        {
            Page = page; Key = key; Title = title; Text = text;
        }

        /// <summary>The page to show, or null to stay on the current one.</summary>
        public Page? Page { get; }
        /// <summary>The control to spotlight, or null for a centred card.</summary>
        public string Key { get; }
        public string Title { get; }
        public string Text { get; }
    }

    /// <summary>
    /// The guided tour: cards that spotlight the main screens and buttons. It only switches pages and
    /// puts back the one the user was on; it never changes anything on the machine.
    /// </summary>
    public sealed partial class TourViewModel : ObservableObject
    {
        private readonly MainViewModel _main;
        private Page _returnTo;

        public TourViewModel(MainViewModel main) { _main = main; }

        private AppServices S => _main.Services;

        /// <summary>Step 0 is the offer; the tour proper is 1 onwards.</summary>
        public static IReadOnlyList<TourStep> Steps { get; } = new[]
        {
            new TourStep(null, null, "New to PktmonGUI?",
                "A one-minute tour of the main screens and buttons. Nothing on this machine changes while it runs."),
            new TourStep(Page.Preflight, "preflight.checks", "Preflight checks",
                "Every launch starts here. These checks decide whether a capture is usable: elevation, pktmon, the working folder, settings, and filters already on the machine. Fix red items before you continue."),
            new TourStep(Page.Preflight, "preflight.adapters", "Capture adapters",
                "Tick the adapters to capture on. They're remembered by MAC address, because pktmon's component IDs change at reboot."),
            new TourStep(Page.Preflight, "preflight.continue", "Continue to capture",
                "Opens the Capture page. Until then nothing on the machine has changed. Preflight stays in the sidebar, to re-run the checks or pick other adapters."),
            new TourStep(Page.Capture, "nav", "Pages",
                "Capture, Counters, Filters and Files. Ctrl+B collapses the sidebar to icons."),
            new TourStep(Page.Capture, "capture.mode", "Capture mode",
                "Live streams packets into the grid. Record writes an .etl file, which loads into the grid after Stop. Counters only counts packets per component."),
            new TourStep(Page.Capture, "capture.options", "Capture options",
                "The adapter, the filter rules (click them to edit), full packets or a snap length, which process owns each packet, and saving a live capture as pcapng. Hover any control for what it does and the pktmon flag behind it."),
            new TourStep(Page.Capture, "capture.start", "Start and Stop",
                "Runs pktmon with the options on the left. However PktmonGUI closes, it stops its capture and leaves the machine's filters as it found them."),
            new TourStep(Page.Capture, "capture.grid", "Packets",
                "Click a header to sort. Type in the box under a title to filter that column, e.g. >1000, 10.0.0.0/8 or !ARP. Find searches every column, and pid:1234 or proc:name filter by process. Select a packet to decode it on the right."),
            new TourStep(Page.Counters, "counters.main", "Counters",
                "Packets and drops per component while a capture runs, with the reason for each drop. In Live mode it also counts packets per rule."),
            new TourStep(Page.Filters, "filters.rules", "Filter rules",
                "Fields on one rule are ANDed and separate rules are ORed, up to 32 rules. Add presets from the right. Filters are machine-wide: ones PktmonGUI didn't set are saved before they're cleared and put back when it closes."),
            new TourStep(Page.Files, "files.list", "Capture files",
                "Every capture in the working folder. Convert an .etl to pcapng or text, add process comments, and open the result in Wireshark."),
            new TourStep(Page.Capture, "session", "Session",
                "What's running right now, on which adapters and with which options. The note under it says which filters are on the machine."),
            new TourStep(null, "titlebar.help", "That's the tour",
                "Click ? or press F1 to take it again. The button beside it switches between the dark and light themes."),
        };

        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(Current), nameof(IsWelcome), nameof(StepText), nameof(NextText), nameof(BackText))]
        [NotifyCanExecuteChangedFor(nameof(BackCommand))]
        private int _index;

        [ObservableProperty] private bool _isOpen;

        public TourStep Current => Steps[Index];
        public bool IsWelcome => Index == 0;
        public bool IsLast => Index == Steps.Count - 1;
        public string StepText => IsWelcome ? null : $"{Index} / {Steps.Count - 1}";
        public string NextText => IsWelcome ? "Show me around" : IsLast ? "Finish" : "Next";
        public string BackText => IsWelcome ? "Not now" : "Back";

        /// <summary>The checkbox on every card. Saved at once, so it holds even if PktmonGUI doesn't close cleanly.</summary>
        public bool DontOfferAtStartup
        {
            get => !S.Settings.ShowTourAtStartup;
            set
            {
                if (value == DontOfferAtStartup) return;
                S.Settings.ShowTourAtStartup = !value;
                S.Store.Save();
                OnPropertyChanged();
            }
        }

        /// <summary>Opens on the offer (at startup) or straight on the first step (? or F1).</summary>
        public void Start(bool offer)
        {
            if (!IsOpen) _returnTo = _main.CurrentPage;
            OnPropertyChanged(nameof(DontOfferAtStartup));
            GoTo(offer ? 0 : 1);
            IsOpen = true;
        }

        private void GoTo(int index)
        {
            var page = Steps[index].Page;
            if (page != null) _main.CurrentPage = page.Value;
            Index = index;
        }

        [RelayCommand]
        private void Next()
        {
            if (IsLast) Close();
            else GoTo(Index + 1);
        }

        private bool CanGoBack => IsWelcome || Index > 1;

        /// <summary>"Not now" on the offer; on the first step there's nothing to go back to.</summary>
        [RelayCommand(CanExecute = nameof(CanGoBack))]
        private void Back()
        {
            if (IsWelcome) Close();
            else GoTo(Index - 1);
        }

        [RelayCommand]
        public void Close()
        {
            if (!IsOpen) return;
            IsOpen = false;
            _main.CurrentPage = _returnTo;
        }
    }
}
