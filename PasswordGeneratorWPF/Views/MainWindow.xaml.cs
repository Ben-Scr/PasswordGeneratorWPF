using BenScr.Security;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace BenScr.PasswordGeneratorWPF
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            PasswordUtility.Initialize();
            InitializeEvents();
        }

        private void InitializeEvents()
        {
            KeyDown += OnKeyDown;
            passwordLengthSlider.ValueChanged += OnPasswordLengthSliderValueChanged;
            passwordLengthTxt.TextChanged += OnPasswordLengthTextChanged;
            generateButton.Click += OnClickGenerateButton;
            copyButton.Click += OnClickCopyButton;
            clearHistoryButton.Click += OnClickClearHistoryButton;
            closeButton.Click += OnClickCloseButton;
            addButton.Click += OnClickAddButton;
            passwordTxt.TextChanged += OnPasswordTextChanged;
            saveToFileButton.Click += OnSaveToFileButtonClick;
        }

        private void OnKeyDown(object sender, KeyEventArgs e)
        {
            if(e.Key == Key.F5)
                GenerateNewPassword();

            else if(e.Key == Key.Left)
                passwordLengthSlider.Value--;
            else if(e.Key == Key.Right)
                passwordLengthSlider.Value++;
        }

        private void OnStrengthProgressbarValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            var bar = (ProgressBar)sender;
            double v = bar.Value;

            if (v < 0.33)
                bar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D83434"));
            else if (v < 0.66)
                bar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E6B325"));
            else
                bar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3CB371"));

            bar.Foreground = new SolidColorBrush(Lerp((Color)ColorConverter.ConvertFromString("#D83434"), (Color)ColorConverter.ConvertFromString("#3CB371"), (float)v));
        }

        private Color Lerp(Color a, Color b, float t)
        {
            Color c = new Color();
            c.R = (byte)(a.R + (b.R- a.R) * t);
            c.G = (byte)(a.G + (b.G - a.G) *t);
            c.B = (byte)(a.B + (b.B - a.B) *t);
            c.A = 255;
            return c;
        }

        private void OnSaveToFileButtonClick(object sender, EventArgs args)
        {
            string[] passwords = new string[passwordHistory.Items.Count];

            if (passwords.Length == 0) return;

            for(int i = 0; i < passwords.Length; i++)
            {
                passwords[i] = passwordHistory.Items[i].ToString();
            }

            string mainPath = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PasswordManager", "Passwords");
            string filename = $"{passwords.Length} {(passwords.Length == 1 ? "Item" : "Items")} long password history from {DateTime.Now.ToString().Replace(":", "-")}.txt";

            Directory.CreateDirectory(mainPath);
            File.WriteAllLines(System.IO.Path.Combine(mainPath, filename), passwords);
            Process.Start("explorer.exe", mainPath);
        }

        private void OnPasswordTextChanged(object sender, EventArgs args)
        {
            string password = passwordTxt.Text;

            if (string.IsNullOrEmpty(password))
            {
                strengthInfoTextbox.Text = "No password";
                strengthProgressbar.Value = 0;
                return;
            }

            BigInteger combinations = PasswordUtility.PossibleCombinations(password);
            strengthProgressbar.Value = PasswordUtility.GetPasswordStrength(password);
            strengthInfoTextbox.Text = GetStrengthInfo(password);
        }

        private void OnClickAddButton(object sender, EventArgs args)
        {
            string password = passwordTxt.Text;
            if (string.IsNullOrEmpty(password) || passwordHistory.Items.Contains(password)) return;
            passwordHistory.Items.Add(password);
        }

        private void OnClickCloseButton(object sender, EventArgs args)
        {
            MessageBoxResult result = MessageBox.Show(
            "Are you sure that you want to quit?",
            "Confirmation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question
            );

            if (result == MessageBoxResult.Yes)
            {
                Environment.Exit(0);
            }
        }

        private void OnClickClearHistoryButton(object sender, EventArgs args)
        {
            passwordHistory.Items.Clear();
        }

        private void OnClickCopyButton(object sender, EventArgs args)
        {
            string psw = passwordTxt.Text;

            if (string.IsNullOrEmpty(psw)) return;

            Clipboard.SetText(psw);
            MessageBox.Show($"Copied \"{psw}\" to the clipboard");
        }

        private void OnPasswordLengthSliderValueChanged(object sender, EventArgs args)
        {
            passwordLengthTxt.Text = passwordLengthSlider.Value.ToString();
        }

        private void OnPasswordLengthTextChanged(object sender, EventArgs args)
        {
            if (int.TryParse(passwordLengthTxt.Text, out int length))
            {
                length = Math.Clamp(length, (int)passwordLengthSlider.Minimum, (int)passwordLengthSlider.Maximum);
                passwordLengthTxt.Text = length.ToString();
                passwordLengthSlider.Value = length;
            }
            else
            {
                passwordLengthSlider.Value = 0;
                passwordLengthTxt.Text = "0";
            }
        }

        private string GetStrengthInfo(string password)
        {
            BigInteger combinations = PasswordUtility.PossibleCombinations(password);
            string classification = "The password " + PasswordUtility.ClassifyPassword(password)+ ".";
            string info = $" Possible Combinations {PasswordUtility.FormattedValue(combinations)}, it would take {PasswordUtility.RequiredTimeToCrack(combinations)} to crack the password";
            return classification + info;
        }

        private void OnClickGenerateButton(object sender, EventArgs args)
        {
            GenerateNewPassword();
        }

        private void GenerateNewPassword()
        {
            int pwdLength = (int)passwordLengthSlider.Value;

            bool upperCase = upperCaseCheckbox.IsChecked ?? false;
            bool lowerCase = lowerCaseCheckbox.IsChecked ?? false;
            bool digits = digitCheckbox.IsChecked ?? false;
            bool specialChars = specialCharsCheckbox.IsChecked ?? false;

            Password pwd = new Password(pwdLength, upperCase, lowerCase, digits, specialChars, includeCharsTxt.Text, excludeCharsTxt.Text);
            string generatedPassword = pwd.Next();
            passwordTxt.Text = generatedPassword;
        }

        private void displayButton_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}