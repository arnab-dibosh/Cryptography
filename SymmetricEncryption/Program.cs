using System;
using System.IO;


namespace SymmetricEncryption
{
    class Program
    {
        static void Main(string[] args) {

            ///////////AES Based
            var key = "b14ca5898a4e4133bbce2ea2315a1916";
            Console.WriteLine("Please enter a string for encryption");
            var str = Console.ReadLine();
            var encryptedString = AesCryptography.EncryptString(key, str);
            Console.WriteLine($"encrypted string = {encryptedString}");
            var decryptedString = AesCryptography.DecryptString(key, encryptedString);
            Console.WriteLine($"decrypted string = {decryptedString}");
            Console.ReadKey();
            ////////////
        }
       
    }

}
