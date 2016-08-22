using System;
using System.Security.Cryptography;

namespace Cryptography
{
    public static class Utility
    {
        public static byte[] GenerateRandomNumber(int length)
        {
            using(var generator = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[length];
                generator.GetBytes(randomNumber);
                return randomNumber;
            }
        }

        public static string ConvertToBase64(byte[] input)
        {
            return Convert.ToBase64String(input);
        }

        public static byte[] ConvertFromBase64(string input)
        {
            return Convert.FromBase64String(input);
        }
    }
}
