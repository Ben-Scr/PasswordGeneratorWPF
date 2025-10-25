
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Windows;

namespace PasswordGenerator
{
    public static class PasswordGen
    {
        private const string DIGITS = "0123456789";
        private const string UPPER_CASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string LOWER_CASE_LETTERS = "abcdefghijklmnopqrstuvwxyz";
        private const string SPECIAL_CHARS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        private static RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();

        public static int CalculateCharsetLength(string password)
        {
            int length = 0;

            if (Regex.IsMatch(password, $"[{Regex.Escape(LOWER_CASE_LETTERS)}]"))
                length += LOWER_CASE_LETTERS.Length;

            if (Regex.IsMatch(password, $"[{Regex.Escape(UPPER_CASE_LETTERS)}]"))
                length += UPPER_CASE_LETTERS.Length;

            if (Regex.IsMatch(password, $"[{Regex.Escape(DIGITS)}]"))
                length += DIGITS.Length;

            foreach(var letter in SPECIAL_CHARS)
            {
                if (password.Contains(letter))
                {
                    length += SPECIAL_CHARS.Length;
                    break;
                }
            }

            return length;
        }


        public static string GenerateCharset(bool upperLetter, bool lowerLetter, bool digits, bool specialChars, string includeChars, string excludeChars)
        {
            string charset = includeChars;

            if (upperLetter) charset += UPPER_CASE_LETTERS;
            if (lowerLetter) charset += LOWER_CASE_LETTERS;
            if (digits) charset += DIGITS;
            if (specialChars) charset += SPECIAL_CHARS;

            if (charset.Length == 0) return "";

            if (excludeChars.Length > 0)
                charset = charset.Replace(excludeChars, "");

            return charset;
        }
        public static string Generate(int length, bool upperLetter, bool lowerLetter, bool digits, bool specialChars, string includeChars, string excludeChars)
        {
            string result = string.Empty;
            string charset = GenerateCharset(upperLetter, lowerLetter, digits, specialChars, includeChars, excludeChars);

            if (string.IsNullOrEmpty(charset)) return "";

            for (int i = 0; i < length; i++)
            {
                result += charset[NextInt(charset.Length)];
            }

            return result;
        }
        public static string Generate(int length, string charset)
        {
            string result = string.Empty;

            if (string.IsNullOrEmpty(charset)) return "";

            for (int i = 0; i < length; i++)
            {
                result += charset[NextInt(charset.Length)];
            }

            return result;
        }
        private static int NextInt(int max)
        {
            byte[] fourBytes = new byte[sizeof(int)];
            randomNumberGenerator.GetBytes(fourBytes);
            int value = BitConverter.ToInt32(fourBytes);
            return (value & int.MaxValue) % max;
        }
    }
}
