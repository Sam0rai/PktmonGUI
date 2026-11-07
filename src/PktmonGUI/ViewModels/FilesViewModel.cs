using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PktmonGUI.Model;
using PktmonGUI.Pcap;
using PktmonGUI.Pktmon;
using PktmonGUI.Services;
using PktmonGUI.Util;

namespace PktmonGUI.ViewModels
{
    public enum ConvertTarget { Pcapng, Text }

    public sealed partial class EtlFileItem : ObservableObject
    {
        /// <summary>Checked in the list's first column, for Delete marked.</summary>
        [ObservableProperty] private bool _isMarked;

        public string Path { get; set; }
        public string Name => System.IO.Path.GetFileName(Path);
        public DateTime Created { get; set; }
        public DateTime Modified { get; set; }
        public long Size { get; set; }
        public CaptureMeta Meta { get; set; }

        /// <summary>For one part of a multi-file capture, the capture's name.etl; otherwise null.</summary>
        public string PartOf { get; set; }
        public bool IsPart => PartOf != null;

        // A part spans from when pktmon opened it to its last write; Meta's times are the whole capture's.
        public DateTime Started => IsPart ? Created : Meta?.Started ?? Modified;
        public string StartedText => Started.ToString("d MMM HH:mm");
        public string Length
        {
            get
            {
                if (IsPart) return FormatLength(Modified - Created);
                return Meta?.Stopped == null ? "—" : FormatLength(Meta.Stopped.Value - Meta.Started);
            }
        }
        private static string FormatLength(TimeSpan d) =>
            d.TotalMinutes >= 1 ? $"{(int)d.TotalMinutes}m {d.Seconds:00}s" : $"{Math.Max(0, d.Seconds)}s";
        public string Packets => IsPart ? "—" : Meta?.Packets?.ToString("N0") ?? "—";
        public string Adapter => Meta == null ? "—" : string.Join(", ", Meta.ComponentNames);
        public bool Wireless => Meta?.Wireless == true;

        /// <summary>A Live capture saved directly as pcapng (no .etl behind it).</summary>
        public bool IsPcapng => Path.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase);
        public string PcapPath => IsPcapng ? Path : System.IO.Path.ChangeExtension(Path, ".pcapng");
        public string TxtPath => System.IO.Path.ChangeExtension(Path, ".txt");
        public bool HasPcap => File.Exists(PcapPath);
        public bool HasTxt => File.Exists(TxtPath);

        /// <summary>The pcapng a multi-file capture's parts were joined into: name.pcapng, beside name1.etl, name2.etl…</summary>
        public bool IsJoined => IsPcapng && IsMultiFile;
        /// <summary>The capture's joined pcapng, for a part or the joined file itself.</summary>
        public string JoinedPath => IsPart ? System.IO.Path.ChangeExtension(PartOf, ".pcapng") : IsJoined ? Path : null;

        public string Converted
        {
            get
            {
                if (IsPcapng)
                {
                    var kind = IsJoined ? "joined parts" : "live";
                    return File.Exists(AttributionPath) ? kind + " · processes" : kind;
                }
                var parts = new List<string>();
                if (HasPcap) parts.Add("pcapng");
                if (IsPart && File.Exists(JoinedPath)) parts.Add("joined");
                if (HasTxt) parts.Add("txt");
                if (parts.Count == 0) return Wireless ? "Wi-Fi: check" : "—";
                return string.Join(" · ", parts);
            }
        }

        public string FiltersText => Meta == null ? "unknown (not recorded by PktmonGUI)"
            : Meta.Filters.Count == 0 ? "none: every packet" : string.Join(", ", Meta.Filters.Select(f => f.ShortLabel));
        public string SnapText => Meta?.PacketSize == null ? "unknown" : Meta.PacketSize == 0 ? "Full packets" : $"{Meta.PacketSize} bytes (truncated)";
        public bool IsMultiFile => Meta?.LogMode == CaptureOptions.LogModeArg(LogMode.MultiFile);
        // pktmon rolls multi-file parts over late (16 MB ETW buffers), so the setting is only a request.
        public string LogModeText => Meta == null ? "unknown"
            : IsMultiFile ? $"multi-file, {Meta.FileSizeMb ?? 512} MB requested · this file {BytesConverter.Format(Size)}"
            : $"{Meta.LogMode}, {Meta.FileSizeMb ?? 512} MB cap";
        public string StoppedText => Meta?.StoppedHow ?? "unknown";
        public string AttributionPath => Attribution.AttributionSnapshot.PathFor(PartOf ?? Path);
        public string ProcessesText => File.Exists(AttributionPath)
            ? (IsPcapng ? "recorded: every packet has a process comment" : "recorded: packets loaded into the grid show their process")
            : "not recorded (Processes was off, or the capture wasn't made by PktmonGUI)";
    }

    public sealed partial class FilesViewModel : ObservableObject
    {
        private readonly MainViewModel _main;
        private AppServices S => _main.Services;
        private List<EtlFileItem> _all = new List<EtlFileItem>();

        public FilesViewModel(MainViewModel main) { _main = main; }

        public ObservableCollection<EtlFileItem> Items { get; } = new ObservableCollection<EtlFileItem>();
        public ObservableCollection<CommandPreview> Preview { get; } = new ObservableCollection<CommandPreview>();

        [ObservableProperty] private EtlFileItem _selected;
        [ObservableProperty] private string _search;
        [ObservableProperty] private ConvertTarget _target = ConvertTarget.Pcapng;
        [ObservableProperty] private string _outputName;
        [ObservableProperty] private bool _dropOnly;
        [ObservableProperty] private string _componentId;
        [ObservableProperty] private bool _textHex;
        [ObservableProperty] private bool _fixWifi;
        [ObservableProperty] private bool _isConverting;
        [ObservableProperty] private string _status;
        [ObservableProperty] private bool _addProcessComments = true;
        [ObservableProperty] private bool _joinParts = true;

        /// <summary>The capture has a recorded attribution sidecar, so packets can get process comments.</summary>
        public bool HasAttribution => Selected != null && File.Exists(Selected.AttributionPath);
        public bool CanAddProcessComments => IsPcap && HasAttribution;
        private const string CommentsStep = "#process-comments";
        private const string JoinStep = "#join";

        /// <summary>Every part of the selected part's multi-file capture, in order; empty for anything else.</summary>
        private IReadOnlyList<string> _parts = new string[0];
        public bool CanJoinParts => Target == ConvertTarget.Pcapng && _parts.Count > 1;
        public string JoinPartsText => $"Join all {_parts.Count} parts into one file";
        private bool Joining => CanJoinParts && JoinParts;

        public string PcapngNote => Selected?.IsJoined == true
            ? "The parts of a multi-file capture, joined into one pcapng. Nothing to convert: open it in Wireshark, or re-apply the process comments."
            : "A Live capture, saved straight to pcapng with the real packet bytes. Nothing to convert: open it in Wireshark, or re-apply the process comments.";

        public string Folder => S.WorkingFolder;
        public string FolderStats
        {
            get
            {
                string free = "";
                try { free = BytesConverter.Format(new DriveInfo(System.IO.Path.GetPathRoot(Folder)).AvailableFreeSpace) + " free · "; } catch { }
                return $"{free}{_all.Count} capture{(_all.Count == 1 ? "" : "s")} · {BytesConverter.Format(_all.Sum(i => i.Size))}";
            }
        }

        public WiresharkInfo Wireshark => S.Wireshark;
        public bool HasWireshark => Wireshark != null;
        public bool ShowWifiFix => Selected?.Wireless == true && !Selected.IsPcapng && Target == ConvertTarget.Pcapng;
        public bool CanUseEditcap => Wireshark?.HasEditcap == true;
        public bool IsPcap => Target == ConvertTarget.Pcapng || IsLivePcapng;
        public bool IsText => Target == ConvertTarget.Text && !IsLivePcapng;
        /// <summary>The selected item is a Live capture already saved as pcapng: nothing to convert, only comments to (re)apply.</summary>
        public bool IsLivePcapng => Selected?.IsPcapng == true;
        public bool IsEtl => Selected != null && !Selected.IsPcapng;

        // ---- Marking (the checkbox column) --------------------------------------------

        private bool _bulkMarking;

        public int MarkedCount => _all.Count(i => i.IsMarked);
        public string DeleteMarkedText => MarkedCount == 0 ? "Delete marked" : $"Delete {MarkedCount} marked";

        /// <summary>The header checkbox: every listed capture marked, none, or some (null).</summary>
        public bool? AllMarked
        {
            get
            {
                int n = Items.Count(i => i.IsMarked);
                return n == 0 ? false : n == Items.Count ? true : (bool?)null;
            }
            set
            {
                _bulkMarking = true;
                foreach (var i in Items) i.IsMarked = value == true;
                _bulkMarking = false;
                OnMarksChanged();
            }
        }

        private void OnItemPropertyChanged(object sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(EtlFileItem.IsMarked) && !_bulkMarking) OnMarksChanged();
        }

        private void OnMarksChanged()
        {
            OnPropertyChanged(nameof(MarkedCount));
            OnPropertyChanged(nameof(DeleteMarkedText));
            OnPropertyChanged(nameof(AllMarked));
            DeleteMarkedCommand.NotifyCanExecuteChanged();
        }

        partial void OnSearchChanged(string value) => ApplySearch();
        partial void OnSelectedChanged(EtlFileItem value)
        {
            _parts = value?.IsPart == true ? CaptureFiles.PartsOf(value.PartOf) : new string[0];
            OnPropertyChanged(nameof(CanJoinParts));
            OnPropertyChanged(nameof(JoinPartsText));
            OnPropertyChanged(nameof(PcapngNote));
            OutputName = DefaultOutputName();
            FixWifi = value?.Wireless == true && CanUseEditcap;
            OnPropertyChanged(nameof(ShowWifiFix));
            OnPropertyChanged(nameof(HasAttribution));
            OnPropertyChanged(nameof(IsLivePcapng));
            OnPropertyChanged(nameof(IsEtl));
            OnPropertyChanged(nameof(IsPcap));
            OnPropertyChanged(nameof(IsText));
            OnPropertyChanged(nameof(CanAddProcessComments));
            BuildPreview();
        }
        partial void OnJoinPartsChanged(bool value)
        {
            OutputName = DefaultOutputName();
            BuildPreview();
        }
        partial void OnTargetChanged(ConvertTarget value)
        {
            OnPropertyChanged(nameof(CanJoinParts));
            OutputName = DefaultOutputName();
            OnPropertyChanged(nameof(ShowWifiFix));
            OnPropertyChanged(nameof(IsPcap));
            OnPropertyChanged(nameof(IsText));
            OnPropertyChanged(nameof(CanAddProcessComments));
            BuildPreview();
        }
        partial void OnAddProcessCommentsChanged(bool value) => BuildPreview();
        partial void OnOutputNameChanged(string value) => BuildPreview();
        partial void OnDropOnlyChanged(bool value) => BuildPreview();
        partial void OnComponentIdChanged(string value) => BuildPreview();
        partial void OnTextHexChanged(bool value) => BuildPreview();
        partial void OnFixWifiChanged(bool value) => BuildPreview();

        [RelayCommand]
        public void Refresh()
        {
            var keep = Selected?.Path;
            var marked = new HashSet<string>(_all.Where(i => i.IsMarked).Select(i => i.Path), StringComparer.OrdinalIgnoreCase);
            _all.Clear();
            try
            {
                if (Directory.Exists(Folder))
                {
                    var dir = new DirectoryInfo(Folder);
                    // .etl recordings, plus Live captures saved straight to pcapng (a pcapng converted
                    // from an .etl sits next to it and belongs to that entry).
                    var files = dir.GetFiles("*.etl").Concat(dir.GetFiles("*.pcapng")
                        .Where(f => !File.Exists(System.IO.Path.ChangeExtension(f.FullName, ".etl"))
                                 && !f.Name.EndsWith("-fixed.pcapng", StringComparison.OrdinalIgnoreCase)));
                    foreach (var f in files)
                    {
                        var item = new EtlFileItem
                        {
                            Path = f.FullName, Created = f.CreationTime, Modified = f.LastWriteTime, Size = f.Length,
                            Meta = CaptureFiles.MetaFor(f.FullName), PartOf = CaptureFiles.ParentOf(f.FullName),
                            IsMarked = marked.Contains(f.FullName),
                        };
                        item.PropertyChanged += OnItemPropertyChanged;
                        _all.Add(item);
                    }
                }
            }
            catch (Exception ex) { Status = ex.Message; }
            _all = _all.OrderByDescending(i => i.Started).ToList();
            ApplySearch();
            Selected = Items.FirstOrDefault(i => i.Path == keep) ?? Items.FirstOrDefault();
            OnPropertyChanged(nameof(Folder));
            OnPropertyChanged(nameof(FolderStats));
            OnPropertyChanged(nameof(Wireshark));
            OnPropertyChanged(nameof(HasWireshark));
            OnMarksChanged();
        }

        private void ApplySearch()
        {
            Items.Clear();
            var q = Search?.Trim();
            foreach (var i in _all.Where(i => string.IsNullOrEmpty(q) || i.Name.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              i.Adapter.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0))
                Items.Add(i);
            OnPropertyChanged(nameof(AllMarked));
        }

        private string DefaultOutputName() => Selected == null ? null
            : System.IO.Path.GetFileName(Joining ? Selected.JoinedPath : Target == ConvertTarget.Pcapng ? Selected.PcapPath : Selected.TxtPath);

        private string OutputPath()
        {
            if (Selected == null) return null;
            var name = string.IsNullOrWhiteSpace(OutputName) ? DefaultOutputName() : OutputName.Trim();
            return System.IO.Path.IsPathRooted(name) ? name : System.IO.Path.Combine(System.IO.Path.GetDirectoryName(Selected.Path), name);
        }

        /// <summary>Where each part is converted before the join; deleted once joined (or on failure).</summary>
        private IReadOnlyList<string> JoinTemps(string outPath) =>
            _parts.Select(p => System.IO.Path.Combine(System.IO.Path.GetDirectoryName(outPath),
                System.IO.Path.GetFileNameWithoutExtension(p) + ".pcapng.tmp")).ToList();

        private string FixedPath(string pcap) => System.IO.Path.Combine(System.IO.Path.GetDirectoryName(pcap),
            System.IO.Path.GetFileNameWithoutExtension(pcap) + "-fixed.pcapng");

        private IEnumerable<PktmonCommand> Plan(bool open)
        {
            if (Selected == null) yield break;
            if (Selected.IsPcapng)
            {
                // Already a pcapng: (re)apply the process comments in place, then open.
                if (CanAddProcessComments && AddProcessComments)
                    yield return new PktmonCommand(new[] { Selected.Path },
                        $"built into PktmonGUI, from {System.IO.Path.GetFileName(Selected.AttributionPath)}; replaces earlier ones", CommentsStep);
                if (open && HasWireshark)
                    yield return new PktmonCommand(new[] { Selected.Path }, null, Wireshark.WiresharkExe);
                yield break;
            }
            var outPath = OutputPath();
            int? comp = int.TryParse(ComponentId, out var c) ? c : (int?)null;
            if (Target == ConvertTarget.Pcapng)
            {
                if (Joining)
                {
                    var temps = JoinTemps(outPath);
                    for (var i = 0; i < _parts.Count; i++)
                        yield return PktmonCommand.Etl2Pcap(_parts[i], temps[i], DropOnly, comp).WithNote($"part {i + 1} of {_parts.Count}");
                    yield return new PktmonCommand(new[] { outPath }.Concat(temps),
                        "built into PktmonGUI: one section, in capture order; the part files are then deleted", JoinStep);
                }
                else
                    yield return PktmonCommand.Etl2Pcap(Selected.Path, outPath, DropOnly, comp);
                if (CanAddProcessComments && AddProcessComments)
                    yield return new PktmonCommand(new[] { outPath },
                        $"built into PktmonGUI, from {System.IO.Path.GetFileName(Selected.AttributionPath)}; in Wireshark: frame.comment", CommentsStep);
                var final = outPath;
                if (ShowWifiFix && FixWifi && CanUseEditcap)
                {
                    final = FixedPath(outPath);
                    yield return new PktmonCommand(new[] { "-T", "ieee-802-11", outPath, final },
                        "experimental: relabels the link type for Wi-Fi captures", Wireshark.EditcapExe);
                }
                if (open && HasWireshark)
                    yield return new PktmonCommand(new[] { final }, null, Wireshark.WiresharkExe);
            }
            else
            {
                yield return PktmonCommand.Etl2Txt(Selected.Path, outPath, verbose: true, hex: TextHex)
                    .WithNote("--verbose is the only way to read CDP and LLDP detail");
            }
        }

        private void BuildPreview()
        {
            Preview.Clear();
            foreach (var cmd in Plan(open: HasWireshark))
                Preview.Add(new CommandPreview(Display(cmd), cmd.Note));
        }

        private string Display(PktmonCommand cmd)
        {
            if (cmd.Executable == "pktmon") return cmd.DisplayText;
            if (cmd.Executable == CommentsStep) return $"(PktmonGUI) add a \"Process: …\" comment to each packet in {System.IO.Path.GetFileName(cmd.Args[0])}";
            if (cmd.Executable == JoinStep) return $"(PktmonGUI) join the {cmd.Args.Count - 1} converted parts into {System.IO.Path.GetFileName(cmd.Args[0])}";
            var exe = System.IO.Path.GetFileName(cmd.Executable);
            var shown = exe.Equals("editcap.exe", StringComparison.OrdinalIgnoreCase) ? "editcap" : PktmonCommand.QuoteArg(cmd.Executable);
            return shown + " " + cmd.ArgumentString;
        }

        [RelayCommand]
        private Task ConvertAsync() => RunPlanAsync(open: false);

        [RelayCommand]
        private Task ConvertOpenAsync() => RunPlanAsync(open: true);

        private async Task RunPlanAsync(bool open)
        {
            if (Selected == null || IsConverting) return;
            if (S.Session.IsActive && S.Session.Options?.Mode == CaptureMode.Record &&
                string.Equals(S.Session.Meta?.EtlFile, Selected.PartOf ?? Selected.Path, StringComparison.OrdinalIgnoreCase))
            {
                Ui.Info("Still recording", "Stop the capture before converting this file.");
                return;
            }
            var outPath = Selected.IsPcapng ? Selected.Path : OutputPath();
            if (!Selected.IsPcapng && File.Exists(outPath) &&
                !Ui.Confirm("Overwrite?", $"{System.IO.Path.GetFileName(outPath)} exists and will be overwritten.", "Overwrite"))
                return;

            IsConverting = true;
            Status = "Converting…";
            string commentSummary = null;
            var temps = Joining ? JoinTemps(outPath) : new string[0];
            int converted = 0;
            try
            {
                foreach (var cmd in Plan(open).ToList())
                {
                    if (cmd.Executable == JoinStep)
                    {
                        Status = $"Joining {temps.Count} parts…";
                        var target = cmd.Args[0];
                        var packets = await Task.Run(() => Pcapng.Join(cmd.Args.Skip(1).ToList(), target));
                        S.Log.Note($"Joined {temps.Count} parts into {System.IO.Path.GetFileName(target)}: {packets:N0} packets");
                        DeleteTemps(temps);
                        continue;
                    }
                    if (cmd.Executable == "pktmon" && temps.Count > 0 && converted < temps.Count)
                        Status = $"Converting part {++converted} of {temps.Count}…";
                    if (cmd.Executable == CommentsStep)
                    {
                        Status = "Adding process comments…";
                        var sidecar = Selected.AttributionPath;
                        var target = cmd.Args[0];
                        var result = await Task.Run(() => EtlConverter.AddProcessComments(target, sidecar));
                        commentSummary = result.ToString();
                        S.Log.Note($"Process comments added to {System.IO.Path.GetFileName(target)}: {commentSummary}");
                        continue;
                    }
                    if (cmd.Executable == Wireshark?.WiresharkExe)
                    {
                        // Wireshark opens the capture at Medium integrity, via Explorer, not with our admin token (see ShellRun).
                        if (ShellRun.TryOpen(cmd.Executable, cmd.ArgumentString)) S.Log.Note("Opened in Wireshark: " + cmd.Args[0]);
                        else Ui.Info("Couldn't start Wireshark", $"Open it yourself and load:\n{cmd.Args[0]}");
                        continue;
                    }
                    var r = await S.Runner.RunAsync(cmd);
                    if (!r.Success) { Ui.Error("Conversion failed", r.Output); Status = "Failed"; return; }
                    Status = r.Output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.Length > 0) ?? "Done";
                }
                // The text file opens in its default handler, also at Medium integrity.
                if (IsText && open && !ShellRun.TryOpen(outPath))
                    Ui.Info("Couldn't open the file", $"Open it yourself:\n{outPath}");
                Status = "Done · " + System.IO.Path.GetFileName(outPath) + (commentSummary == null ? "" : " · " + commentSummary);
            }
            catch (Exception ex) { Ui.Error("Conversion failed", ex); Status = "Failed"; }
            finally
            {
                DeleteTemps(temps);
                IsConverting = false;
                Refresh();
            }
        }

        private static void DeleteTemps(IEnumerable<string> temps)
        {
            foreach (var t in temps)
                try { if (File.Exists(t)) File.Delete(t); } catch { }
        }

        [RelayCommand]
        private void OpenFolder() => Ui.OpenInExplorer(Folder);

        [RelayCommand]
        private void ShowInFolder()
        {
            if (Selected != null) Ui.OpenInExplorer(Selected.Path, select: true);
        }

        [RelayCommand]
        private void Delete()
        {
            if (Selected != null) DeleteCaptures(new[] { Selected });
        }

        [RelayCommand(CanExecute = nameof(CanDeleteMarked))]
        private void DeleteMarked() => DeleteCaptures(_all.Where(i => i.IsMarked).ToList());
        private bool CanDeleteMarked() => MarkedCount > 0;

        /// <summary>The Delete key: the marked captures if any, else the selected one.</summary>
        [RelayCommand]
        private void DeleteMarkedOrSelected()
        {
            if (MarkedCount > 0) DeleteMarked();
            else Delete();
        }

        /// <summary>
        /// Deletes captures with their sidecars (meta, processes) and conversions, after one
        /// confirmation. The file the running capture is writing is left alone.
        /// </summary>
        private void DeleteCaptures(IReadOnlyList<EtlFileItem> items)
        {
            var busy = items.Where(IsBeingWritten).ToList();
            items = items.Except(busy).ToList();
            if (items.Count == 0)
            {
                if (busy.Count > 0) Ui.Info("Still capturing", $"{busy[0].Name} is being written by the running capture. Stop it first.");
                return;
            }

            var files = FilesToDelete(items);
            const int listed = 15;
            var message = "Deletes:\n" + string.Join("\n", files.Take(listed).Select(System.IO.Path.GetFileName)) +
                          (files.Count > listed ? $"\n… and {files.Count - listed} more" : "") +
                          (busy.Count > 0 ? "\n\nSkipped, still being written: " + string.Join(", ", busy.Select(b => b.Name)) : "");
            if (!Ui.Confirm(items.Count == 1 ? "Delete capture?" : $"Delete {items.Count} captures?", message, "Delete", danger: true)) return;

            var failed = new List<string>();
            foreach (var f in files)
            {
                try { File.Delete(f); }
                catch (Exception ex) { failed.Add(System.IO.Path.GetFileName(f) + ": " + ex.Message); }
            }
            if (failed.Count > 0) Ui.Error(failed.Count == 1 ? "Couldn't delete a file" : $"Couldn't delete {failed.Count} files", string.Join("\n", failed));
            Refresh();
        }

        /// <summary>The captures' files that exist, with their sidecars (meta, processes) and conversions.</summary>
        internal static List<string> FilesToDelete(IReadOnlyList<EtlFileItem> items)
        {
            bool Deleting(string path) => items.Any(i => string.Equals(i.Path, path, StringComparison.OrdinalIgnoreCase));
            var files = new List<string>();
            var multiFile = new HashSet<string>(StringComparer.OrdinalIgnoreCase); // name.etl of each multi-file capture touched
            foreach (var i in items)
            {
                if (i.IsPart) files.AddRange(new[] { i.Path, i.PcapPath, i.TxtPath });
                else if (i.IsJoined) files.Add(i.Path);
                else files.AddRange(new[] { i.Path, CaptureSession.MetaPathFor(i.Path), i.AttributionPath, i.PcapPath, i.TxtPath });
                if (i.IsPart || i.IsJoined) multiFile.Add(i.PartOf ?? System.IO.Path.ChangeExtension(i.Path, ".etl"));
            }
            // A multi-file capture's metadata and process data are shared by its parts and the pcapng they
            // were joined into: they go with the last of those.
            foreach (var etl in multiFile)
            {
                var joined = System.IO.Path.ChangeExtension(etl, ".pcapng");
                if (CaptureFiles.PartsOf(etl).All(Deleting) && (!File.Exists(joined) || Deleting(joined)))
                    files.AddRange(new[] { CaptureSession.MetaPathFor(etl), Attribution.AttributionSnapshot.PathFor(etl) });
            }
            return files.Distinct(StringComparer.OrdinalIgnoreCase).Where(File.Exists).ToList();
        }

        private bool IsBeingWritten(EtlFileItem item) =>
            S.Session.IsActive && S.Session.Meta?.Stopped == null &&
            string.Equals(S.Session.Meta?.EtlFile, item.PartOf ?? item.Path, StringComparison.OrdinalIgnoreCase);

        [RelayCommand]
        private void CopyPreview() => Ui.CopyText(string.Join(Environment.NewLine, Preview.Select(p => p.Text)));

        [RelayCommand]
        private void SetTarget(ConvertTarget t) => Target = t;
    }
}
