using BenScr.Security;
using System.Diagnostics;
using System.IO;
using System.Numerics;

namespace BenScr
{
    internal static class Utility
    {
        static readonly string MainPath = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PasswordManager", "Passwords");

        public static string GetStrengthInfo(string password)
        {
            BigInteger combinations = PasswordUtility.PossibleCombinations(password);
            string classification = "The password " + PasswordUtility.ClassifyPassword(password) + ".";
            string info = $" Possible Combinations {PasswordUtility.FormattedValue(combinations)}, it would take {PasswordUtility.RequiredTimeToCrack(combinations)} to crack the password";
            return classification + info;
        }

        public static void SavePasswordHistory(string[] passwords)
        {

            string filename = $"{passwords.Length} {(passwords.Length == 1 ? "Item" : "Items")} long password history from {DateTime.Now.ToString().Replace(":", "-")}.txt";

            Directory.CreateDirectory(MainPath);
            File.WriteAllLines(System.IO.Path.Combine(MainPath, filename), passwords);
            Process.Start("explorer.exe", MainPath);
        }
    }
}
