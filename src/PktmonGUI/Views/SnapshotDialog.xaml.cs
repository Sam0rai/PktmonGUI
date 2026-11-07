using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using PktmonGUI.Model;
using PktmonGUI.Services;
using PktmonGUI.ViewModels;

namespace PktmonGUI.Views
{
    /// <summary>
    /// Shown before PktmonGUI clears filters it didn't create (mockup board 6), and as a
    /// read-only review of the machine's filters from Preflight.
    /// </summary>
    public partial class SnapshotDialog : Window
    {
        private readonly MachineFilters _machine;
        private bool? _result;

        private SnapshotDialog(MachineFilters machine)
        {
            InitializeComponent();
            _machine = machine;
            Owner = Application.Current?.MainWindow;
            FilterGrid.ItemsSource = machine.Filters;
            OwnerText.Text = machine.Owner;
            MouseLeftButtonDown += (s, e) => { if (e.ButtonState == MouseButtonState.Pressed && e.GetPosition(this).Y < 40) try { DragMove(); } catch { } };
        }

        /// <summary>Returns null on cancel, true to snapshot + restore on stop, false to clear without a snapshot.</summary>
        public static bool? ShowApply(MachineFilters machine, IReadOnlyList<FilterRule> rules, string snapshotFolder)
        {
            var d = new SnapshotDialog(machine);
            int n = machine.Count;
            d.TitleText.Text = "Snapshot before clearing";
            d.Headline.Text = $"Applying {(rules.Count == 0 ? "no rules" : rules.Count == 1 ? "this rule" : "these rules")} will clear {n} filter{(n == 1 ? "" : "s")} this tool did not create";
            d.Explain.Text = $"pktmon keeps one filter set per machine and only clears it all at once. There is no way to delete a single rule. Everything below belongs to another owner on {Environment.MachineName}.";
            d.PathRun.Text = Path.Combine(snapshotFolder, DateTime.Now.ToString("yyyy-MM-dd'T'HHmmss") + ".json");
            d.ApplyButton.Content = rules.Count == 0 ? $"Clear all {n}" : $"Clear all {n} and apply my {rules.Count} rule{(rules.Count == 1 ? "" : "s")}";
            var unparsed = machine.Filters.Count(f => !f.FullyParsed);
            if (unparsed > 0)
                d.Explain.Text += $"\n\n{unparsed} of them use fields PktmonGUI couldn't read back, so they'll be kept as text in the snapshot and must be re-added by hand.";
            d.ShowDialog();
            if (d._result == null) return null;
            return d._result.Value && d.SaveCheck.IsChecked == true;
        }

        public static void ShowReview(MachineFilters machine)
        {
            var d = new SnapshotDialog(machine);
            d.TitleText.Text = "Filters on this machine";
            d.Headline.Text = $"{machine.Count} filter{(machine.Count == 1 ? "" : "s")} on {Environment.MachineName}";
            d.Explain.Text = "Filters are machine-wide: one set, shared by every signed-in admin and by services such as Defender for Endpoint. Fields on one rule are ANDed; separate rules are ORed.";
            d.SnapshotPanel.Visibility = Visibility.Collapsed;
            d.ApplyButton.Visibility = Visibility.Collapsed;
            d.CancelButton.Content = "Close";
            d.ShowDialog();
        }

        private void Apply_Click(object sender, RoutedEventArgs e) { _result = true; Close(); }
        private void Cancel_Click(object sender, RoutedEventArgs e) { _result = null; Close(); }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            var text = _machine.Raw + Environment.NewLine + Environment.NewLine + "# as filter add commands" + Environment.NewLine +
                       string.Join(Environment.NewLine, _machine.Filters.Select(f => Pktmon.PktmonCommand.FilterAdd(f.Rule).DisplayText));
            Ui.CopyText(text);
        }
    }
}
