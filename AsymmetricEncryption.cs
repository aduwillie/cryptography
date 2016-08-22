using System;
using System.Security.Cryptography;

namespace Cryptography
{
    public interface IAsymmetricEncryption
    {
        void AssignNewKey();
        byte[] Encrypt(byte[] toBeEncrypted);
        byte[] Decrypt(byte[] toBeDecrypted);
    }

    public class RSAWithParameterKey : IAsymmetricEncryption
    {
        public RSAWithParameterKey()
        {
            AssignNewKey();
        }

        RSAParameters _publicKey;
        RSAParameters _privateKey;
        
        public void AssignNewKey()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                _publicKey = rsa.ExportParameters(false);
                _privateKey = rsa.ExportParameters(true);
            }
        }

        public byte[] Encrypt(byte[] toBeEncrypted)
        {
            byte[] cipherBytes;
            using(var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_publicKey);
                cipherBytes = rsa.Encrypt(toBeEncrypted, true);
            }
            return cipherBytes;
        }

        public byte[] Decrypt(byte[] toBeDecrypted)
        {
            byte[] plain;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_privateKey);
                plain = rsa.Decrypt(toBeDecrypted, true);
            }
            return plain;
        }
    }
}
