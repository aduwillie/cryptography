using System.Security.Cryptography;

namespace Cryptography
{
    public class HMAC
    {
        public byte[] ComputeHMACMD5(byte[] tobeHashed, byte[] key)
        {
            using (var hmac = new HMACMD5(key))
            {
                return hmac.ComputeHash(tobeHashed);
            }
        }

        public byte[] ComputeHMACSHA256(byte[] tobeHashed, byte[] key)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(tobeHashed);
            }
        }

        public byte[] ComputeHMACSHA384(byte[] tobeHashed, byte[] key)
        {
            using (var hmac = new HMACSHA384(key))
            {
                return hmac.ComputeHash(tobeHashed);
            }
        }

        public byte[] ComputeHMACSHA512(byte[] tobeHashed, byte[] key)
        {
            using (var hmac = new HMACSHA512(key))
            {
                return hmac.ComputeHash(tobeHashed);
            }
        }
    }
}
