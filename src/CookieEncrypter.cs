namespace IO.Curity.OAuthAgent
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using IO.Curity.OAuthAgent.Exceptions;
    using IO.Curity.OAuthAgent.Utilities;

    /*
     * Implements modern authenticated symmetric encryption and decryption via the Microsoft libraries
     */
    public class CookieEncrypter
    {
        private const int VERSION_SIZE = 1;
        private const int GCM_IV_SIZE = 12;
        private const int GCM_TAG_SIZE = 16;
        private const int CURRENT_VERSION = 1;

        public static string EncryptCookie(string encKeyHex, string cookieToEncrypt) {
            
            byte[] plaintext = Encoding.UTF8.GetBytes(cookieToEncrypt);

            var iv = new byte[GCM_IV_SIZE];
            RandomNumberGenerator.Create().GetBytes(iv);

            var key = Convert.FromHexString(encKeyHex);
            (byte[] ciphertext, byte[] tag) = AesGcmEncrypt(plaintext, key, iv);
            byte[] version = BitConverter.GetBytes(CURRENT_VERSION);

            if (BitConverter.IsLittleEndian) {
                Array.Reverse(version);
            }

            byte[] versionToEncode = version.TakeLast(VERSION_SIZE).ToArray();
            byte[] result = versionToEncode.Concat(iv).Concat(ciphertext).Concat(tag).ToArray();
            return Base64UrlEncoder.Encode(result);
        }

        public static string DecryptCookie(string encKeyHex, string base64CipherText) {
            
            byte[] allBytes = Base64UrlEncoder.Decode(base64CipherText);

            var minSize = VERSION_SIZE + GCM_IV_SIZE + 1 + GCM_TAG_SIZE;
            if (allBytes.Length < minSize)
            {
                throw new InvalidCookieException("The received cookie has an invalid length");
            }

            if (allBytes[0] != CURRENT_VERSION)
            {
                throw new InvalidCookieException("The received cookie has an invalid format");
            }

            byte[] version = allBytes.Take(VERSION_SIZE).ToArray();
            byte[] iv = allBytes.Skip(VERSION_SIZE).Take(GCM_IV_SIZE).ToArray();          
            byte[] ciphertext = allBytes.Skip(VERSION_SIZE + GCM_IV_SIZE).Take(allBytes.Length - (VERSION_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE)).ToArray();
            byte[] tag = allBytes.TakeLast(GCM_TAG_SIZE).ToArray();

            try
            {
                var key = Convert.FromHexString(encKeyHex);
                byte[] plaintext = AesGcmDecrypt(ciphertext, key, iv, tag);
                return Encoding.UTF8.GetString(plaintext);
            }
            catch (Exception ex)
            {
                throw new CookieDecryptionException(ex);
            }
        }

        private static (byte [], byte[]) AesGcmEncrypt(byte[] plaintext, byte[] key, byte[] iv) {
            
            AesGcm aesgcm = new AesGcm(key, GCM_TAG_SIZE);
            byte[] tag = new byte[GCM_TAG_SIZE];
            byte[] ciphertext = new byte[plaintext.Length];
            aesgcm.Encrypt(iv, plaintext, ciphertext, tag);

            return (ciphertext, tag);
        }

        private static byte[] AesGcmDecrypt(byte[] ciphertext, byte[] key, byte[] iv, byte[] tag) {
            
            AesGcm aesgcm = new AesGcm(key, GCM_TAG_SIZE);
            byte[] plaintext = new byte[ciphertext.Length];
            aesgcm.Decrypt(iv, ciphertext, tag, plaintext);
            return plaintext;
        }
    }
}
