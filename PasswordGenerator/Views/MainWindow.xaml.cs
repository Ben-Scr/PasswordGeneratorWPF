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

namespace PasswordGenerator
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

        private void strengthProgressbar_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            var bar = (ProgressBar)sender;
            double v = bar.Value; // 0..1

            // Schwellen kannst du anpassen
            if (v < 0.33)
                bar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D83434"));
            else if (v < 0.66)
                bar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E6B325"));
            else
                bar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3CB371"));
        }

        public void OnSaveToFileButtonClick(object sender, EventArgs args)
        {
            string[] passwords = new string[passwordHistory.Items.Count];

            if (passwords.Length == 0) return;

            for(int i = 0; i < passwordHistory.Items.Count; i++)
            {
                passwords[i] = passwordHistory.Items[i].ToString();
            }

            string mainPath = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PasswordManager", "Passwords");
            string filename = $"{passwords.Length} {(passwords.Length == 1 ? "Item" : "Items")} long password history from {DateTime.Now.ToString().Replace(":", "-")}.txt";
            Directory.CreateDirectory(mainPath);
            File.WriteAllLines(System.IO.Path.Combine(mainPath, filename), passwords);
            Process.Start("explorer.exe", mainPath);
        }

        public void OnPasswordTextChanged(object sender, EventArgs args)
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

        public void OnClickAddButton(object sender, EventArgs args)
        {
            string password = passwordTxt.Text;
            if (string.IsNullOrEmpty(password) || passwordHistory.Items.Contains(password)) return;
            passwordHistory.Items.Add(password);
        }

        public void OnClickCloseButton(object sender, EventArgs args)
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

        public void OnClickClearHistoryButton(object sender, EventArgs args)
        {
            passwordHistory.Items.Clear();
        }

        public void OnClickCopyButton(object sender, EventArgs args)
        {
            string psw = passwordTxt.Text;

            if (string.IsNullOrEmpty(psw)) return;

            Clipboard.SetText(psw);
            MessageBox.Show($"Copied \"{psw}\" to the clipboard");
        }

        public void OnPasswordLengthSliderValueChanged(object sender, EventArgs args)
        {
            passwordLengthTxt.Text = passwordLengthSlider.Value.ToString();
        }

        public void OnPasswordLengthTextChanged(object sender, EventArgs args)
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

        public string GetStrengthInfo(string password)
        {
            BigInteger combinations = PasswordUtility.PossibleCombinations(password);
            string classification = "The password " + PasswordUtility.ClassifyPassword(password)+ ".";
            string info = $" Possible Combinations {PasswordUtility.FormattedValue(combinations)}, it would take {PasswordUtility.RequiredTimeToCrack(combinations)} to crack the password";
            return classification + info;
        }

        public void OnClickGenerateButton(object sender, EventArgs args)
        {
            int pswLength = (int)passwordLengthSlider.Value;

            bool upperCase = upperCaseCheckbox.IsChecked ?? false;
            bool lowerCase = lowerCaseCheckbox.IsChecked ?? false;
            bool digits = digitCheckbox.IsChecked ?? false;
            bool specialChars = specialCharsCheckbox.IsChecked ?? false;

            string charset = PasswordGen.GenerateCharset(upperCase, lowerCase, digits, specialChars, includeCharsTxt.Text, excludeCharsTxt.Text);
            string generatedPassword = PasswordGen.Generate(pswLength, charset);
            passwordTxt.Text = generatedPassword;
        }

        private void displayButton_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}