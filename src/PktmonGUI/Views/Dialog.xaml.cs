using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace PktmonGUI.Views
{
    public enum DialogButtons { Ok, OkCancel, YesNo, YesNoCancel }
    public enum DialogKind { Info, Warning, Error, Question }
    public enum DialogResultKind { None, Ok, Cancel, Yes, No }

    /// <summary>Dark replacement for MessageBox, matching the app's chrome.</summary>
    public partial class Dialog : Window
    {
        private DialogResultKind _result = DialogResultKind.None;

        private Dialog() { InitializeComponent(); }

        public static DialogResultKind Show(Window owner, string title, string message,
                                            DialogButtons buttons = DialogButtons.Ok, DialogKind kind = DialogKind.Info,
                                            string detail = null, string yesText = null, string noText = null)
        {
            var d = Create(owner, title, message, kind, detail);
            switch (buttons)
            {
                case DialogButtons.Ok: d.AddButton("OK", DialogResultKind.Ok, primary: true, isDefault: true, isCancel: true); break;
                case DialogButtons.OkCancel:
                    d.AddButton("Cancel", DialogResultKind.Cancel, isCancel: true);
                    d.AddButton(yesText ?? "OK", DialogResultKind.Ok, primary: true, isDefault: true, danger: kind == DialogKind.Warning);
                    break;
                case DialogButtons.YesNo:
                    d.AddButton(noText ?? "No", DialogResultKind.No, isCancel: true);
                    d.AddButton(yesText ?? "Yes", DialogResultKind.Yes, primary: true, isDefault: true);
                    break;
                case DialogButtons.YesNoCancel:
                    d.AddButton("Cancel", DialogResultKind.Cancel, isCancel: true);
                    d.AddButton(noText ?? "No", DialogResultKind.No);
                    d.AddButton(yesText ?? "Yes", DialogResultKind.Yes, primary: true, isDefault: true);
                    break;
            }
            d.ShowDialog();
            return d._result == DialogResultKind.None
                ? (buttons == DialogButtons.Ok ? DialogResultKind.Ok : DialogResultKind.Cancel)
                : d._result;
        }

        /// <summary>Asks for one line of text. Returns null on cancel.</summary>
        public static string Prompt(Window owner, string title, string message, string initial = "")
        {
            var d = Create(owner, title, message, DialogKind.Question, null);
            d.InputBox.Visibility = Visibility.Visible;
            d.InputBox.Text = initial ?? "";
            d.AddButton("Cancel", DialogResultKind.Cancel, isCancel: true);
            d.AddButton("OK", DialogResultKind.Ok, primary: true, isDefault: true);
            d.Loaded += (s, e) => { d.InputBox.Focus(); d.InputBox.SelectAll(); };
            d.ShowDialog();
            return d._result == DialogResultKind.Ok ? d.InputBox.Text.Trim() : null;
        }

        private static Dialog Create(Window owner, string title, string message, DialogKind kind, string detail)
        {
            var d = new Dialog
            {
                Owner = owner != null && owner.IsLoaded ? owner : null,
                Title = title,
            };
            if (d.Owner == null) d.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            d.TitleText.Text = title;
            d.MessageText.Text = message;
            if (!string.IsNullOrEmpty(detail))
            {
                d.DetailBox.Text = detail;
                d.DetailBox.Visibility = Visibility.Visible;
            }
            string icon = "I.Info", brush = "B.Accent";
            switch (kind)
            {
                case DialogKind.Warning: icon = "I.Warn"; brush = "B.Warn"; break;
                case DialogKind.Error: icon = "I.Cross"; brush = "B.Bad"; break;
                case DialogKind.Question: icon = "I.Info"; brush = "B.Accent"; break;
            }
            d.KindIcon.Data = (Geometry)d.FindResource(icon);
            d.KindIcon.SetResourceReference(System.Windows.Shapes.Shape.StrokeProperty, brush);
            d.MouseLeftButtonDown += (s, e) => { if (e.ButtonState == MouseButtonState.Pressed) try { d.DragMove(); } catch { } };
            return d;
        }

        private void AddButton(string text, DialogResultKind result, bool primary = false, bool isDefault = false,
                               bool isCancel = false, bool danger = false)
        {
            var b = new Button
            {
                Content = text,
                Margin = new Thickness(8, 0, 0, 0),
                MinWidth = 84,
                IsDefault = isDefault,
                IsCancel = isCancel,
            };
            if (danger) b.Style = (Style)FindResource("Btn.Danger");
            else if (primary) b.Style = (Style)FindResource("Btn.Primary");
            b.Click += (s, e) => { _result = result; Close(); };
            ButtonsPanel.Children.Add(b);
        }
    }
}
