namespace PktmonGUI.Util
{
    /// <summary>
    /// Tooltip content: a plain-language explanation, with the pktmon flag (or command) behind the
    /// control on its own line. Rendered by the Hint DataTemplate in Themes/Controls.xaml.
    /// </summary>
    public sealed class Hint
    {
        public string Text { get; set; }
        public string Flag { get; set; }
    }
}
