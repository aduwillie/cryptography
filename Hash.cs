using System.Security.Cryptography;

namespace Cryptography
{
    public class Hash
    {
        public byte[] ComputeMD5Hash(byte[] toBeHashed)
        {
            using(var md5 = MD5.Create())
            {
                return md5.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeSHA256Hash(byte[] tobeHashed)
        {
            using(var sha = SHA256.Create())
            {
                return sha.ComputeHash(tobeHashed);
            }
        }

        public static byte[] ComputeSHA384Hash(byte[] tobeHashed)
        {
            using (var sha = SHA384.Create())
            {
                return sha.ComputeHash(tobeHashed);
            }
        }

        public static byte[] ComputeSHA512Hash(byte[] tobeHashed)
        {
            using (var sha = SHA512.Create())
            {
                return sha.ComputeHash(tobeHashed);
            }
        }
    }
}
