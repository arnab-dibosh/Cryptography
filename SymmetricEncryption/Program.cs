using System;
using System.IO;


namespace SymmetricEncryption
{
    class Program
    {
        static void Main(string[] args) {

            
            string salt = "1234", pin = "pin", biccode = "sblbic", vid = "arnab@user.idtp";

            for (int i = 0; i < 1000; i++) {
                string combinedString = AesCryptography.ProcessPin(pin, biccode, vid, salt);
                string dycryptedpinbic = AesCryptography.RetriveAndStorePin(biccode, vid, salt, combinedString);

                //Validate
                string hasedPinBic = AesCryptography.HashSha512(pin + biccode);
                string doubleHasedPinBic = AesCryptography.HashSha512(hasedPinBic);
                string message;
                if (dycryptedpinbic.Equals(doubleHasedPinBic)) message = "Valid User";
                else message = "Invalid User";
                Console.WriteLine(message);
            }            

            //Test plain encryption decryption
            //Console.WriteLine("Please enter a string for encryption");
            //var str = Console.ReadLine();
            //var encryptedString = AesCryptography.EncryptString(key, salt, str);
            //Console.WriteLine($"encrypted string = {encryptedString}");
            //var decryptedString = AesCryptography.DecryptString(key, salt, encryptedString);
            //Console.WriteLine($"decrypted string = {decryptedString}");
            //Console.ReadKey();
        }

    }

}
