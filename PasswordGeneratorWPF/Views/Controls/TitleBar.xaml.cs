using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace PasswordGeneratorWPF.Views.Controls
{
    public partial class TitleBar : UserControl
    {
        public TitleBar() => InitializeComponent();

        private void OnDrag(object sender, MouseButtonEventArgs e)
        {
            var win = Window.GetWindow(this);
            if (e.ClickCount == 2) Toggle(win);
            else win?.DragMove();
        }

        private void Minimize_Click(object s, RoutedEventArgs e)
        { var w = Window.GetWindow(this); SystemCommands.MinimizeWindow(w); }

        private void MaximizeRestore_Click(object s, RoutedEventArgs e)
        { var w = Window.GetWindow(this); Toggle(w); }

        private void Close_Click(object s, RoutedEventArgs e)
        { var w = Window.GetWindow(this); SystemCommands.CloseWindow(w); }

        private static void Toggle(Window? w)
        {
            if (w == null) return;
            if (w.WindowState == WindowState.Normal) SystemCommands.MaximizeWindow(w);
            else SystemCommands.RestoreWindow(w);
        }
    }
}
