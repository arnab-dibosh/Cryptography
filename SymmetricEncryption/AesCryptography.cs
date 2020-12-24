using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SymmetricEncryption
{
    public class AesCryptography
    {
        public static string EncryptString(string key, string salt, string plainText) {

            byte[] array;

            using (Aes aes = Aes.Create()) {
                
                byte[] saltArr = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
                byte[] keyArr = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
                byte[] rawsaltBytes = Encoding.UTF8.GetBytes(salt), rawkeyBytes = Encoding.UTF8.GetBytes(key);

                Array.Copy(rawsaltBytes, saltArr, rawsaltBytes.Length >= 16 ? 16 : rawsaltBytes.Length);
                Array.Copy(rawkeyBytes, keyArr, rawkeyBytes.Length >= 16 ? 16 : rawkeyBytes.Length);
                aes.Key = keyArr;
                aes.IV = saltArr;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream()) {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write)) {
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream)) {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }

        public static string DecryptString(string key, string salt, string cipherText) {

            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create()) {

                byte[] saltArr = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
                byte[] keyArr = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
                byte[] rawsaltBytes = Encoding.UTF8.GetBytes(salt), rawkeyBytes = Encoding.UTF8.GetBytes(key);

                Array.Copy(rawsaltBytes, saltArr, rawsaltBytes.Length >= 16 ? 16 : rawsaltBytes.Length);
                Array.Copy(rawkeyBytes, keyArr, rawkeyBytes.Length >= 16 ? 16 : rawkeyBytes.Length);
                aes.Key = keyArr;
                aes.IV = saltArr;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer)) {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read)) {
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream)) {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

        public static string HashSha512(string input) {
            var bytes = Encoding.UTF8.GetBytes(input);
            using (SHA512 shaM = new SHA512Managed()) {
                return Convert.ToBase64String(shaM.ComputeHash(bytes));
            }

        }

        public static string ProcessPin(string pin, string biccode, string vid, string salt) {

            string hashedPinBic = HashSha512(pin + biccode);
            string uuid = Guid.NewGuid().ToString();
            string part1 = EncryptString(uuid, salt, hashedPinBic);
            string part2 = EncryptString(biccode, vid, uuid);
            var lengthPaded = part1.Length.ToString().PadLeft(4, '0');
            string output = $"{lengthPaded}{part1}{part2}";

            return output;
        }

        public static string RetriveAndStorePin(string biccode, string vid, string salt, string hashText) {

            int part1Len = Convert.ToInt32(hashText.Substring(0, 4));
            string part1 = hashText.Substring(4, part1Len);
            string part2 = hashText.Substring(4 + part1Len);

            string uuid = DecryptString(biccode, vid, part2);
            string hashedPinBic = DecryptString(uuid, salt, part1);

            string doubleHashedPinBic = HashSha512(hashedPinBic);

            return doubleHashedPinBic;
        }
    }
}
