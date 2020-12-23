using System;
using System.IO;


namespace SymmetricEncryption
{
    class Program
    {
        static void Main(string[] args) {
           
            var key = "b14ca5898a4e4133bbce2ea2315a1916";
            var IV = "1234567887654321";
            Console.WriteLine("Please enter a string for encryption");
            var str = Console.ReadLine();
            var encryptedString = AesCryptography.EncryptString(key, IV,str);
            Console.WriteLine($"encrypted string = {encryptedString}");
            var decryptedString = AesCryptography.DecryptString(key, IV, encryptedString);
            Console.WriteLine($"decrypted string = {decryptedString}");
            Console.ReadKey();
        }
       
    }

}
