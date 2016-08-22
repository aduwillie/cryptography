using System;
using System.Security.Cryptography;

namespace Cryptography
{
    public class PasswordHash
    {
        public byte[] MD5PasswordWithSalt(byte[] toBeHashed, byte[] salt)
        {
            return Hash.ComputeMD5Hash(Combine(toBeHashed, salt));
        }

        public byte[] SHA256PasswordWithSalt(byte[] toBeHashed, byte[] salt)
        {
            return Hash.ComputeSHA256Hash(Combine(toBeHashed, salt));
        }

        public byte[] SHA384PasswordWithSalt(byte[] toBeHashed, byte[] salt)
        {
            return Hash.ComputeSHA384Hash(Combine(toBeHashed, salt));
        }

        public byte[] SHA512PasswordWithSalt(byte[] toBeHashed, byte[] salt)
        {
            return Hash.ComputeSHA512Hash(Combine(toBeHashed, salt));
        }

        public byte[] PBKDF2PasswordWithSalt(byte[] toBeHashed, byte[] salt, int noOfRounds)
        {
            using (var hash = new Rfc2898DeriveBytes(toBeHashed, salt, noOfRounds))
            {
                return hash.GetBytes(32);
            }
        }

        public byte[] PBKDF2PasswordWithSalt(string toBeHashed, byte[] salt, int noOfRounds)
        {
            using (var hash = new Rfc2898DeriveBytes(toBeHashed, salt, noOfRounds))
            {
                return hash.GetBytes(32);
            }
        }

        byte[] Combine(byte[] first, byte[] second)
        {
            var ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }
    }
}
