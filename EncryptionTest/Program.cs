using System;

namespace EncryptionTest
{
    class Program
    {
        private static string secretKey = "C7n9gyHq1txsXbtiLVLqiETbrXyhw7Jw";
        static void Main(string[] args)
        {
            string urlAuthToken = args[0];
            string urlToken = URLEncryption.Decryption(urlAuthToken, secretKey);
            Console.WriteLine(urlToken);
        }
    }
}
