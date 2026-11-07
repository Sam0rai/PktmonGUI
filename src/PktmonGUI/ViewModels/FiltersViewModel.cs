using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PktmonGUI.Model;
using PktmonGUI.Pktmon;
using PktmonGUI.Services;
using PktmonGUI.Util;

namespace PktmonGUI.ViewModels
{
    public sealed class CommandPreview
    {
        public CommandPreview(string text, string note = null, bool isNote = false) { Text = text; Note = note; IsNote = isNote; }
        public string Text { get; }
        public string Note { get; }
        /// <summary>A comment line (<c># …</c>) rather than a command.</summary>
        public bool IsNote { get; }
        public bool Failed => false;
        public bool IsRunning => false;
        public string Output => null;
    }

    /// <summary>A filter on the machine that isn't in the list: Apply to machine removes it unless it's kept.</summary>
    public sealed class MachineOnlyFilter
    {
        public MachineOnlyFilter(ExistingFilter filter, FilterRule rule, string setBy)
        {
            Filter = filter;
            Rule = rule;
            SetBy = setBy;
        }

        public ExistingFilter Filter { get; }
        public FilterRule Rule { get; }
        public string SetBy { get; }
        public string Title => string.IsNullOrWhiteSpace(Rule.Name) ? $"Filter {Filter.Index}" : Rule.Name.Trim();
        public string Args => Rule.ArgsSummary;
        /// <summary>Only a filter read back in full can be put back in the list.</summary>
        public bool CanKeep => Filter.FullyParsed;
        public string KeepTip => CanKeep
            ? "Put it back in your list, so Apply to machine keeps it"
            : "PktmonGUI couldn't read every field of this filter, so it can't recreate it. Line from pktmon filter list: " + Filter.RawText;
    }

    public sealed partial class FiltersViewModel : ObservableObject
    {
        private readonly MainViewModel _main;
        private AppServices S => _main.Services;
        private bool _suspend;

        public FiltersViewModel(MainViewModel main)
        {
            _main = main;
            _suspend = true;
            foreach (var r in main.Services.Settings.DraftRules ?? new List<FilterRule>())
                Rules.Add(new RuleViewModel(this, r));
            _suspend = false;
            Reindex();
            LoadPresets();
            main.Services.Filters.Changed += (s, e) => Ui.Post(() => { OnPropertyChanged(nameof(Machine)); RefreshDerived(); });
        }

        public ObservableCollection<RuleViewModel> Rules { get; } = new ObservableCollection<RuleViewModel>();
        public ObservableCollection<Preset> BuiltInPresets { get; } = new ObservableCollection<Preset>();
        public ObservableCollection<Preset> SavedPresets { get; } = new ObservableCollection<Preset>();
        public ObservableCollection<CommandPreview> ApplyPreview { get; } = new ObservableCollection<CommandPreview>();
        /// <summary>Filters on the machine that no rule in the list matches.</summary>
        public ObservableCollection<MachineOnlyFilter> Removed { get; } = new ObservableCollection<MachineOnlyFilter>();

        public MachineFilters Machine => S.Filters.Current;

        [ObservableProperty] private string _presetSearch;
        [ObservableProperty] private bool _isApplying;

        public string PresetsPath => S.Store.PresetsPath;
        public int RuleCount => Rules.Count;
        public bool AtLimit => Rules.Count >= FilterRule.MaxRules;
        public bool AnyInvalid => Rules.Any(r => !r.IsValid);
        public bool IsCapturing => S.Session.IsActive;

        /// <summary>The draft differs from what's on the machine.</summary>
        public bool IsDirty
        {
            get
            {
                var mine = Signature(CurrentRules());
                if (Machine.AreOurs) return mine != Signature(S.Settings.AppliedRules ?? new List<FilterRule>());
                return mine.Length > 0; // nothing of ours on the machine yet
            }
        }

        private static string Signature(IEnumerable<FilterRule> rules) =>
            string.Join("\n", rules.Select(r => string.Join(" ", r.ToArgs())));

        /// <summary>Apply to machine would change something: the list differs, or the machine has filters the list doesn't.</summary>
        public bool HasPendingChanges => IsDirty || Removed.Count > 0;

        public bool HasRemoved => Removed.Count > 0;

        public string RemovedHeader => Removed.Count == 1
            ? "On the machine, not in your list: Apply to machine removes it"
            : $"On the machine, not in your list: Apply to machine removes these {Removed.Count}";

        private static string FilterCount(int n) => n == 1 ? "1 filter" : $"{n} filters";

        public string StatusText
        {
            get
            {
                if (IsCapturing) return "A capture is running. Changes apply on the next start.";
                if (!HasPendingChanges) return Machine.Count == 0 ? "No filters on the machine." : "These rules are on the machine.";
                if (Rules.Count == 0) return $"List empty. Apply to machine removes the {FilterCount(Machine.Count)} on it.";
                return "Not applied yet. Apply to machine sends these changes.";
            }
        }

        public string MachineBanner
        {
            get
            {
                var m = Machine;
                if (m.Count == 0) return null;
                if (m.AreOurs) return null;
                return $"PktmonGUI didn't set the {FilterCount(m.Count)} on this machine (likely owner: {m.Owner}). " +
                       "There is one filter set per machine, shared by every signed-in admin and by services such as Defender for Endpoint, " +
                       "and pktmon can only clear it all at once: Apply to machine replaces every one of them with your list.";
            }
        }

        /// <summary>Plain-English reading of the whole set: rule sentences ORed together.</summary>
        public string SetSentence
        {
            get
            {
                if (Rules.Count == 0)
                    return Machine.Count == 0
                        ? "No rules: every packet on the adapter is captured."
                        : $"No rules. Until you apply, {(Machine.Count == 1 ? "the machine's filter still decides" : $"the machine's {Machine.Count} filters still decide")} " +
                          "what a capture sees; after Apply to machine, every packet on the adapter is captured.";
                var parts = Rules.Select(r => "(" + r.Sentence + ")");
                return "This set captures a packet when " + string.Join(" or ", parts) + ".";
            }
        }

        public IEnumerable<Preset> FilteredBuiltIn => Match(BuiltInPresets);
        public IEnumerable<Preset> FilteredSaved => Match(SavedPresets);

        private IEnumerable<Preset> Match(IEnumerable<Preset> list) =>
            string.IsNullOrWhiteSpace(PresetSearch) ? list :
            list.Where(p => p.Name.IndexOf(PresetSearch, StringComparison.OrdinalIgnoreCase) >= 0 ||
                            p.Summary.IndexOf(PresetSearch, StringComparison.OrdinalIgnoreCase) >= 0);

        partial void OnPresetSearchChanged(string value)
        {
            OnPropertyChanged(nameof(FilteredBuiltIn));
            OnPropertyChanged(nameof(FilteredSaved));
        }

        public IEnumerable<FilterRule> CurrentRules() => Rules.Select(r => r.ToRule());

        internal void OnRuleChanged()
        {
            if (_suspend) return;
            RefreshDerived();
        }

        private void RefreshDerived()
        {
            UpdateStatuses();
            OnPropertyChanged(nameof(RuleCount));
            OnPropertyChanged(nameof(AtLimit));
            OnPropertyChanged(nameof(AnyInvalid));
            OnPropertyChanged(nameof(IsDirty));
            OnPropertyChanged(nameof(HasPendingChanges));
            OnPropertyChanged(nameof(HasRemoved));
            OnPropertyChanged(nameof(RemovedHeader));
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(MachineBanner));
            OnPropertyChanged(nameof(SetSentence));
            OnPropertyChanged(nameof(IsCapturing));
            foreach (var r in Rules) r.RefreshErrors();
            BuildPreview();
            ApplyCommand.NotifyCanExecuteChanged();
            AddRuleCommand.NotifyCanExecuteChanged();
            ClearDraftCommand.NotifyCanExecuteChanged();
            KeepMachineFilterCommand.NotifyCanExecuteChanged();
            S.Settings.DraftRules = CurrentRules().ToList();
            _main.Capture?.OnRulesChanged();
        }

        private void Reindex()
        {
            // One refresh for the whole renumbering, not one per rule.
            _suspend = true;
            for (int i = 0; i < Rules.Count; i++) Rules[i].Index = i + 1;
            _suspend = false;
            RefreshDerived();
        }

        /// <summary>
        /// The machine's filters, each with the rule it is: for filters PktmonGUI applied, the exact rule it sent;
        /// for anyone else's, what could be read back from <c>pktmon filter list</c>.
        /// </summary>
        private List<(ExistingFilter Filter, FilterRule Rule)> MachineRules()
        {
            var m = Machine;
            var applied = S.Settings.AppliedRules;
            if (m.AreOurs && applied != null && applied.Count == m.Count)
                return m.Filters.Select((f, i) => (f, applied[i])).ToList();
            return m.Filters.Select(f => (f, f.Rule)).ToList();
        }

        /// <summary>
        /// Compares the list with the machine: each rule is On machine, Changed or Not applied, and machine
        /// filters that no rule accounts for go to <see cref="Removed"/>.
        /// </summary>
        private void UpdateStatuses()
        {
            var unmatched = MachineRules().Select(m => (m.Filter, m.Rule, Key: m.Rule.MatchKey)).ToList();
            var rest = new List<(RuleViewModel Vm, FilterRule Rule)>();

            // First, rules that match a machine filter as they stand.
            foreach (var vm in Rules)
            {
                var rule = vm.ToRule();
                var key = rule.MatchKey;
                int i = unmatched.FindIndex(m => m.Key == key);
                if (i < 0) { rest.Add((vm, rule)); continue; }
                SetStatus(vm, rule, unmatched[i].Rule);
                vm.OriginKey = key;
                unmatched.RemoveAt(i);
            }
            // Then edited ones, through the filter they were last seen as.
            foreach (var (vm, rule) in rest)
            {
                int i = vm.OriginKey == null ? -1 : unmatched.FindIndex(m => m.Key == vm.OriginKey);
                if (i < 0)
                {
                    vm.Status = RuleStatus.New;
                    vm.AppliedAs = null;
                    continue;
                }
                SetStatus(vm, rule, unmatched[i].Rule);
                unmatched.RemoveAt(i);
            }

            var setBy = Machine.AreOurs ? "Applied by PktmonGUI" : $"Not set by PktmonGUI (likely owner: {Machine.Owner})";
            Removed.Clear();
            foreach (var m in unmatched) Removed.Add(new MachineOnlyFilter(m.Filter, m.Rule, setBy));
        }

        private static void SetStatus(RuleViewModel vm, FilterRule rule, FilterRule onMachine)
        {
            bool same = rule.MatchKey == onMachine.MatchKey &&
                        string.Equals(rule.Name?.Trim() ?? "", onMachine.Name?.Trim() ?? "", StringComparison.Ordinal);
            vm.Status = same ? RuleStatus.Applied : RuleStatus.Changed;
            vm.AppliedAs = same ? null : string.Join(" ", onMachine.ToArgs().Select(PktmonCommand.QuoteArg));
        }

        private void BuildPreview()
        {
            ApplyPreview.Clear();
            var m = Machine;
            if (m.HasForeign)
                ApplyPreview.Add(new CommandPreview("pktmon filter list", $"saved to snapshots\\{DateTime.Now:yyyy-MM-dd'T'HHmm}….json"));
            if (m.Count > 0)
            {
                ApplyPreview.Add(new CommandPreview("pktmon filter remove", m.Count == 1 ? "clears 1 filter" : $"clears all {m.Count}, the only granularity pktmon has"));
                // Name the ones that won't come back, so the remove isn't a blind one.
                foreach (var r in Removed)
                    ApplyPreview.Add(new CommandPreview($"removes {r.Title}: {r.Args}", isNote: true));
            }
            int i = 0;
            foreach (var r in Rules)
                ApplyPreview.Add(new CommandPreview(r.CommandText, i++ == 1 ? "rules are OR'd" : null));
        }

        public async Task RefreshMachineAsync()
        {
            try { await S.Filters.ReadAsync(); }
            catch { }
        }

        // ---- Rule editing -----------------------------------------------------------

        [RelayCommand(CanExecute = nameof(CanAdd))]
        private void AddRule()
        {
            foreach (var r in Rules) r.IsEditing = false;
            var vm = new RuleViewModel(this, new FilterRule(), editing: true) { IsNew = true };
            Rules.Add(vm);
            Reindex();
        }

        private bool CanAdd() => Rules.Count < FilterRule.MaxRules;

        internal void BeginEdit(RuleViewModel rule)
        {
            foreach (var r in Rules) r.IsEditing = ReferenceEquals(r, rule);
        }

        /// <summary>
        /// The first other rule that matches exactly the same packets, or null. With <paramref name="earlierOnly"/>,
        /// only rules above it count, so of two identical rules just the second is flagged.
        /// </summary>
        internal RuleViewModel FindDuplicate(RuleViewModel rule, bool earlierOnly = false)
        {
            var key = rule.ToRule().MatchKey;
            foreach (var r in Rules)
            {
                if (ReferenceEquals(r, rule))
                {
                    if (earlierOnly) return null;
                    continue;
                }
                if (r.ToRule().MatchKey == key) return r;
            }
            return null;
        }

        /// <summary>Done on a rule card: a rule that repeats another isn't added (if new) or isn't closed (if edited).</summary>
        internal void CommitEdit(RuleViewModel rule)
        {
            var dup = FindDuplicate(rule);
            if (dup != null)
            {
                var other = string.IsNullOrWhiteSpace(dup.Name) ? $"rule {dup.Index}" : $"rule {dup.Index} ({dup.Name.Trim()})";
                if (rule.IsNew)
                {
                    Ui.Error("Filter already exists", $"This filter matches the same packets as {other}, so it wasn't added again.");
                    RemoveRule(rule);
                }
                else
                    Ui.Error("Filter already exists", $"Rule {rule.Index} now matches the same packets as {other}. Change a field, or remove one of them.");
                return;
            }
            rule.IsEditing = false;
            OnRuleChanged();
        }

        internal void RemoveRule(RuleViewModel rule)
        {
            Rules.Remove(rule);
            Reindex();
        }

        internal void DuplicateRule(RuleViewModel rule)
        {
            if (Rules.Count >= FilterRule.MaxRules) return;
            var copy = rule.ToRule();
            copy.Name = string.IsNullOrEmpty(copy.Name) ? null : copy.Name + " (copy)";
            var vm = new RuleViewModel(this, copy) { IsNew = true };
            Rules.Insert(Rules.IndexOf(rule) + 1, vm);
            BeginEdit(vm);
            Reindex();
        }

        internal void Move(RuleViewModel rule, int delta)
        {
            int i = Rules.IndexOf(rule), j = i + delta;
            if (i < 0 || j < 0 || j >= Rules.Count) return;
            Rules.Move(i, j);
            Reindex();
        }

        [RelayCommand(CanExecute = nameof(HasRules))]
        private void ClearDraft()
        {
            if (Rules.Count == 0) return;
            int n = Machine.Count;
            var message = n == 0
                ? "This empties the list on this page. The machine has no filters, so nothing there changes."
                : $"This empties the list on this page only. The {FilterCount(n)} on the machine stay in place until you click Apply to machine. " +
                  $"Until then {(n == 1 ? "it's" : "they're")} shown under the list, marked to be removed, each with a Keep button.";
            if (!Ui.Confirm("Clear the list?", message, "Clear list")) return;
            Rules.Clear();
            Reindex();
        }

        private bool HasRules() => Rules.Count > 0;

        // ---- Presets ----------------------------------------------------------------

        private void LoadPresets()
        {
            BuiltInPresets.Clear();
            foreach (var p in BuiltIn.Presets) BuiltInPresets.Add(p);
            SavedPresets.Clear();
            foreach (var p in S.Store.LoadPresets()) SavedPresets.Add(p);
            OnPropertyChanged(nameof(FilteredBuiltIn));
            OnPropertyChanged(nameof(FilteredSaved));
        }

        [RelayCommand]
        private void AddPreset(Preset preset)
        {
            if (preset == null) return;
            // Rules already in the draft (or repeated within the preset) aren't added twice.
            var keys = new HashSet<string>(CurrentRules().Select(r => r.MatchKey));
            var fresh = preset.Rules.Where(r => keys.Add(r.MatchKey)).ToList();
            int skipped = preset.Rules.Count - fresh.Count;
            if (fresh.Count == 0)
            {
                Ui.Error("Filter already exists", preset.Rules.Count == 1
                    ? $"\"{preset.Name}\" is already in the list, so it wasn't added again."
                    : $"All {preset.Rules.Count} rules in \"{preset.Name}\" are already in the list, so none were added.");
                return;
            }
            int room = FilterRule.MaxRules - Rules.Count;
            if (fresh.Count > room)
            {
                Ui.Error("Too many rules", $"pktmon allows {FilterRule.MaxRules} filters; \"{preset.Name}\" adds {fresh.Count} and there's room for {room}.");
                return;
            }
            foreach (var r in Rules) r.IsEditing = false;
            _suspend = true;
            foreach (var r in fresh) Rules.Add(new RuleViewModel(this, r.Clone()));
            _suspend = false;
            Reindex();
            if (skipped > 0)
                Ui.Error("Some filters already exist", $"{skipped} of the {preset.Rules.Count} rules in \"{preset.Name}\" were already in the list and weren't added again. The other {fresh.Count} were added.");
        }

        [RelayCommand]
        private void SavePreset()
        {
            if (Rules.Count == 0) { Ui.Info("Nothing to save", "Add some rules first."); return; }
            var name = Ui.Prompt("Save as preset", $"Name for these {Rules.Count} rule(s). Saved to presets.json beside the exe.");
            if (string.IsNullOrWhiteSpace(name)) return;
            var existing = SavedPresets.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                if (!Ui.Confirm("Replace preset?", $"A preset called \"{name}\" exists. Replace it?", "Replace")) return;
                SavedPresets.Remove(existing);
            }
            SavedPresets.Add(new Preset { Name = name, Rules = CurrentRules().Select(r => r.Clone()).ToList() });
            PersistPresets();
        }

        [RelayCommand]
        private void DeletePreset(Preset preset)
        {
            if (preset == null || preset.BuiltIn) return;
            if (!Ui.Confirm("Delete preset?", $"Delete \"{preset.Name}\" from presets.json?", "Delete", danger: true)) return;
            SavedPresets.Remove(preset);
            PersistPresets();
        }

        private void PersistPresets()
        {
            try { S.Store.SavePresets(SavedPresets.ToList()); }
            catch (Exception ex) { Ui.Error("Couldn't save presets", ex); }
            OnPropertyChanged(nameof(FilteredSaved));
        }

        [RelayCommand]
        private void ImportJson()
        {
            var path = Ui.OpenFile("Import rules or presets", "JSON (*.json)|*.json|All files|*.*");
            if (path == null) return;
            try
            {
                var text = System.IO.File.ReadAllText(path);
                // Accept a list of presets (presets.json), a single preset, a snapshot, or a bare list of rules.
                List<Preset> presets = null;
                try { presets = Json.Deserialize<List<Preset>>(text); } catch { }
                if (presets != null && presets.Count > 0 && presets.All(p => p.Rules != null && p.Rules.Count > 0))
                {
                    foreach (var p in presets) { p.BuiltIn = false; SavedPresets.Add(p); }
                    PersistPresets();
                    Ui.Info("Imported", $"{presets.Count} preset(s) added to Saved.");
                    return;
                }
                List<FilterRule> rules = null;
                try { rules = Json.Deserialize<List<FilterRule>>(text); } catch { }
                if (rules == null || rules.Count == 0)
                {
                    try { rules = Json.Deserialize<Preset>(text)?.Rules; } catch { }
                }
                if (rules == null || rules.Count == 0)
                {
                    try { rules = Json.Deserialize<FilterSnapshot>(text)?.Rules; } catch { }
                }
                if (rules == null || rules.Count == 0) { Ui.Error("Nothing to import", "The file has no rules PktmonGUI recognizes."); return; }
                AddPreset(new Preset { Name = System.IO.Path.GetFileNameWithoutExtension(path), Rules = rules });
            }
            catch (Exception ex) { Ui.Error("Import failed", ex); }
        }

        [RelayCommand]
        private void ExportJson()
        {
            if (Rules.Count == 0) { Ui.Info("Nothing to export", "Add some rules first."); return; }
            var path = Ui.SaveFile("Export rules", "JSON (*.json)|*.json", "pktmon-rules.json");
            if (path == null) return;
            try { Json.Save(path, new Preset { Name = System.IO.Path.GetFileNameWithoutExtension(path), Rules = CurrentRules().ToList() }); }
            catch (Exception ex) { Ui.Error("Export failed", ex); }
        }

        [RelayCommand]
        private void CopyPreview() => Ui.CopyText(string.Join(Environment.NewLine, ApplyPreview.Select(p => p.Text)));

        // ---- Apply ------------------------------------------------------------------

        // Greyed out once the machine holds the list: applying it again would change nothing.
        private bool CanApply() => !IsApplying && !AnyInvalid && !S.Session.IsActive && HasPendingChanges;

        [RelayCommand(CanExecute = nameof(CanApply))]
        private async Task ApplyAsync()
        {
            IsApplying = true;
            ApplyCommand.NotifyCanExecuteChanged();
            try
            {
                var machine = await S.Filters.ReadAsync();
                bool snapshot = false, restore = false;
                if (machine.HasForeign && S.Snapshots.Active == null)
                {
                    var decision = Views.SnapshotDialog.ShowApply(machine, CurrentRules().ToList(), S.Snapshots.Folder);
                    if (decision == null) return;
                    snapshot = decision.Value;
                    restore = decision.Value;
                }
                else if (machine.HasForeign && S.Snapshots.Active != null)
                {
                    // Foreign rules appeared after we already took a snapshot this session: they'd be lost.
                    if (!Ui.Confirm("Filters changed on this machine",
                        $"There are {machine.Count} filters PktmonGUI didn't set, added after this session's snapshot. Applying clears them without a snapshot.",
                        "Clear and apply", danger: true)) return;
                }
                await S.Filters.ApplyAsync(CurrentRules().ToList(), snapshot, restore);
                foreach (var r in Rules) r.IsEditing = false;
            }
            catch (Exception ex)
            {
                Ui.Error("Couldn't apply the filters", ex.Message, "The machine may now hold only some of the rules. Use Refresh to see what's there.");
                await RefreshMachineAsync();
            }
            finally
            {
                IsApplying = false;
                RefreshDerived();
                _main.RefreshSessionCard();
            }
        }

        [RelayCommand]
        private async Task ClearMachineAsync()
        {
            var m = await S.Filters.ReadAsync();
            if (m.Count == 0) { Ui.Info("Already clear", "There are no filters on this machine."); return; }
            if (m.HasForeign && S.Snapshots.Active == null)
            {
                var decision = Views.SnapshotDialog.ShowApply(m, new List<FilterRule>(), S.Snapshots.Folder);
                if (decision == null) return;
                await S.Filters.ClearAsync(decision.Value, decision.Value);
            }
            else
            {
                // Name every filter that goes, not just how many.
                var list = string.Join(Environment.NewLine, MachineRules().Select(x =>
                    $"{x.Filter.Index,2}  {string.Join(" ", x.Rule.ToArgs().Select(PktmonCommand.QuoteArg))}"));
                if (!Ui.Confirm("Remove all filters from the machine?",
                        $"Runs pktmon filter remove, which deletes {(m.Count == 1 ? "the filter" : $"all {m.Count} filters")} below from the machine. " +
                        "The list on this page stays as it is.",
                        "Remove from machine", danger: true, detail: list)) return;
                await S.Filters.ClearAsync(false, false);
            }
            RefreshDerived();
        }

        [RelayCommand]
        private void LoadFromMachine()
        {
            var m = Machine;
            if (m.Count == 0) { Ui.Info("Nothing there", "The machine has no filters to load."); return; }
            if (Rules.Count > 0 && !Ui.Confirm("Replace your list?", $"Replace the {Rules.Count} rule(s) in your list with the {FilterCount(m.Count)} on the machine?", "Replace")) return;
            _suspend = true;
            Rules.Clear();
            foreach (var x in MachineRules()) Rules.Add(new RuleViewModel(this, x.Rule.Clone()));
            _suspend = false;
            Reindex();
        }

        /// <summary>Keep on a filter marked to be removed: puts it back in the list, so Apply leaves it on the machine.</summary>
        [RelayCommand(CanExecute = nameof(CanKeep))]
        private void KeepMachineFilter(MachineOnlyFilter filter)
        {
            if (!CanKeep(filter)) return;
            foreach (var r in Rules) r.IsEditing = false;
            Rules.Add(new RuleViewModel(this, filter.Rule.Clone()) { OriginKey = filter.Rule.MatchKey });
            Reindex();
        }

        private bool CanKeep(MachineOnlyFilter filter) => filter != null && filter.CanKeep && Rules.Count < FilterRule.MaxRules;

        [RelayCommand]
        private async Task RestoreSnapshotAsync()
        {
            if (!S.Snapshots.HasPendingRestore) return;
            if (S.Session.IsActive) { Ui.Info("Capture running", "Stop the capture first."); return; }
            var failures = await S.Snapshots.RestoreAsync();
            await RefreshMachineAsync();
            S.Settings.AppliedFilterListRaw = null;
            if (failures.Count > 0) Ui.Error("Some filters couldn't be restored", "Add these back by hand:", string.Join(Environment.NewLine, failures));
            _main.RefreshSessionCard();
            RefreshDerived();
        }

        public bool HasSnapshot => S.Snapshots.HasPendingRestore;
    }
}
