using System;
using System.IO;
using System.Security.Cryptography;

namespace Cryptography
{
    public class SymmetricEncryption
    {
        public byte[] DESEncrypt(byte[] toBeEncrypted, byte[] key, byte[] iv)
        {
            return DESEncryption.Encrypt(toBeEncrypted, key, iv);
        }

        public byte[] DESDecrypt(byte[] toBeDecrypted, byte[] key, byte[] iv)
        {
            return DESEncryption.Decrypt(toBeDecrypted, key, iv);
        }

        public byte[] TripleDESEncrypt(byte[] toBeEncrypted, byte[] key, byte[] iv)
        {
            return TripleDESEncryption.Encrypt(toBeEncrypted, key, iv);
        }

        public byte[] TripleDESDecrypt(byte[] toBeDecrypted, byte[] key, byte[] iv)
        {
            return TripleDESEncryption.Decrypt(toBeDecrypted, key, iv);
        }

        public byte[] AESEncrypt(byte[] toBeEncrypted, byte[] key, byte[] iv)
        {
            return AESEncryption.Encrypt(toBeEncrypted, key, iv);
        }

        public byte[] AESDecrypt(byte[] toBeDecrypted, byte[] key, byte[] iv)
        {
            return AESEncryption.Decrypt(toBeDecrypted, key, iv);
        }
    }

    public static class DESEncryption
    {
        public static byte[] Encrypt(byte[] toBeEncrypted, byte[] key, byte[] iv)
        {
            using(var des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;
                des.Key = key;
                des.IV = iv;
                
                using(var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
                    cryptoStream.Write(toBeEncrypted, 0, toBeEncrypted.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        public static byte[] Decrypt(byte[] toBeDecrypted, byte[] key, byte[] iv)
        {
            using (var des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;
                des.Key = key;
                des.IV = iv;

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
                    cryptoStream.Write(toBeDecrypted, 0, toBeDecrypted.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
    }

    public static class TripleDESEncryption
    {
        public static byte[] Encrypt(byte[] toBeEncrypted, byte[] key, byte[] iv)
        {
            using (var des = new TripleDESCryptoServiceProvider())
            {
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;
                des.Key = key;
                des.IV = iv;

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
                    cryptoStream.Write(toBeEncrypted, 0, toBeEncrypted.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        public static byte[] Decrypt(byte[] toBeDecrypted, byte[] key, byte[] iv)
        {
            using (var des = new TripleDESCryptoServiceProvider())
            {
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;
                des.Key = key;
                des.IV = iv;

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
                    cryptoStream.Write(toBeDecrypted, 0, toBeDecrypted.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
    }

    public static class AESEncryption
    {
        public static byte[] Encrypt(byte[] toBeEncrypted, byte[] key, byte[] iv)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
                    cryptoStream.Write(toBeEncrypted, 0, toBeEncrypted.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        public static byte[] Decrypt(byte[] toBeDecrypted, byte[] key, byte[] iv)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);
                    cryptoStream.Write(toBeDecrypted, 0, toBeDecrypted.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
    }
}
