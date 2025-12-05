using BenScr.Security;
using System.Diagnostics;
using System.IO;
using System.Numerics;

namespace BenScr
{
    internal static class Utility
    {
        static readonly string MainDirPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BenScr", "PasswordManager");

        public static string GetStrengthInfo(string password)
        {
            BigInteger combinations = PasswordUtility.PossibleCombinations(password);
            string classification = "The password " + PasswordUtility.ClassifyPassword(password) + ".";
            string info = $" Possible Combinations {PasswordUtility.FormattedValue(combinations)}, it would take {PasswordUtility.RequiredTimeToCrack(combinations)} to crack the password";
            return classification + info;
        }

        public static string GetFilePath()
        {
            string filename = $"PASSWORDS-{DateTime.Now.ToString().Replace(":", "-")}.txt";
            return Path.Combine(MainDirPath, filename);
        }

        public static void SavePasswordHistory(string[] passwords)
        {
            Directory.CreateDirectory(MainDirPath);
            File.WriteAllLines(GetFilePath(), passwords);
            Process.Start("explorer.exe", MainDirPath);
        }
    }
}
