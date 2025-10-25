using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Konscious.Security.Cryptography;

namespace PasswordGenerator
{
    public static class PasswordHasher
    {
        private const int Argon2MemoryKb = 64 * 1024;
        private const int Argon2Iterations = 3;
        private const int Argon2Parallelism = 1;
        private const int SaltSize = 16;
        private const int HashSize = 32;

        public static string ToHash(string password)
        {
            if (password is null) throw new ArgumentNullException(nameof(password));
            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

            var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                MemorySize = Argon2MemoryKb,
                Iterations = Argon2Iterations,
                DegreeOfParallelism = Argon2Parallelism
            };

            byte[] hash = argon.GetBytes(HashSize);

            string saltB64 = Convert.ToBase64String(salt);
            string hashB64 = Convert.ToBase64String(hash);

            return $"argon2id${Argon2MemoryKb}${Argon2Iterations}${Argon2Parallelism}${saltB64}${hashB64}";
        }


        public static byte[] ToHashBytes(string password)
        {
            if (password is null) throw new ArgumentNullException(nameof(password));
            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

            var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                MemorySize = Argon2MemoryKb,
                Iterations = Argon2Iterations,
                DegreeOfParallelism = Argon2Parallelism
            };

            return argon.GetBytes(HashSize);
        }

        public static bool VerifyHash(string password, string stored)
        {
            if (password is null) throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrWhiteSpace(stored)) return false;

            var parts = stored.Split('$');
            if (parts.Length == 6 && parts[0] == "argon2id")
            {
                int memoryKb = int.Parse(parts[1]);
                int iterations = int.Parse(parts[2]);
                int parallel = int.Parse(parts[3]);
                byte[] salt = Convert.FromBase64String(parts[4]);
                byte[] expectedHash = Convert.FromBase64String(parts[5]);

                var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
                {
                    Salt = salt,
                    MemorySize = memoryKb,
                    Iterations = iterations,
                    DegreeOfParallelism = parallel
                };

                byte[] computed = argon.GetBytes(expectedHash.Length);
                return CryptographicEquals(expectedHash, computed);
            }

            if (parts.Length == 4 && parts[0] == "pbkdf2")
            {
                int iterations = int.Parse(parts[1]);
                byte[] salt = Convert.FromBase64String(parts[2]);
                byte[] expectedHash = Convert.FromBase64String(parts[3]);

                using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
                byte[] computed = pbkdf2.GetBytes(expectedHash.Length);
                return CryptographicEquals(expectedHash, computed);
            }

            return false;
        }

        private static bool CryptographicEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
