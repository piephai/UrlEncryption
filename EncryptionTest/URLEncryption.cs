using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography;

namespace EncryptionTest
{
    /// <summary>
    /// Used for encrypting the urlAuthToken
    /// </summary>
    public class URLEncryption
    {
        private static readonly int saltSize = 32;

        /// <summary>
        /// Encrypt the URLAuthToken using AES + RFC. The initialisation vector is different
        /// </summary>
        /// <param name="urlAuthToken"></param>
        /// <param name="secretKey"></param>
        /// <param name="logger"></param>
        /// <returns>encrypted string</returns>
        public static string Encryption(string urlAuthToken, string secretKey)
        {
            if (string.IsNullOrEmpty(urlAuthToken))
            {
                Console.WriteLine("URL auth token cannot be null", "ERROR");
            }
            if (string.IsNullOrEmpty(secretKey))
            {
                Console.WriteLine("Secret key cannot be null", "ERROR");
            }

            //Create a new key derivation function
            using (var keyDerived = new Rfc2898DeriveBytes(secretKey, saltSize))
            {
                var saltBytes = keyDerived.Salt;
                var keyBytes = keyDerived.GetBytes(32);
                var initialisationVectorBytes = keyDerived.GetBytes(16);

                //Create a aes instance then create a new encryptor as well as a new stream

                using (var aesManaged = new AesManaged())
                {
                    using (var encryptor = aesManaged.CreateEncryptor(keyBytes, initialisationVectorBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                using (var streamWriter = new StreamWriter(cryptoStream))
                                {
                                    streamWriter.Write(urlAuthToken);
                                }
                                var cypherTextBytes = memoryStream.ToArray();
                                //Make room for the cypher text to be added together with the salt bytes
                                Array.Resize(ref saltBytes, saltBytes.Length + cypherTextBytes.Length);
                                //Put the the cypher text after the sale bytes
                                Array.Copy(cypherTextBytes, 0, saltBytes, saltSize, cypherTextBytes.Length);
                                Console.WriteLine("Encyption: " + Convert.ToBase64String(saltBytes), "INFO");
                                //Return the whole salt bytes as string
                                return Convert.ToBase64String(saltBytes);
                            }
                        }
                    }
                }

            }
        }

        /// <summary>
        /// Decrypt a cypher text 
        /// </summary>
        /// <param name="encryptedURL"></param>
        /// <param name="secretKey"></param>
        /// <param name="logger"></param>
        /// <returns>decrypted string</returns>
        public static string Decryption(string encryptedURL, string secretKey)
        {
            if (string.IsNullOrEmpty(encryptedURL))
            {
                Console.WriteLine("URL auth token cannot be null", "ERROR");
            }
            if (string.IsNullOrEmpty(secretKey))
            {
                Console.WriteLine("Secret key cannot be null", "ERROR");
            }

            var fullBytes = Convert.FromBase64String(encryptedURL);
            //Put to variable the salt bytes
            var saltBytes = fullBytes.Take(saltSize).ToArray();
            //Put to variable only the cipher text
            var cipherTextBytes = fullBytes.Skip(saltSize).Take(fullBytes.Length - saltSize).ToArray();

            using (var keyDerived = new Rfc2898DeriveBytes(secretKey, saltBytes))
            {
                //Create an aes instance then create a new encryptor as well as a new stream
                var keyBytes = keyDerived.GetBytes(32);
                var initialisationVectorBytes = keyDerived.GetBytes(16);

                using (var aesManaged = new AesManaged())
                {
                    using (var decryptor = aesManaged.CreateDecryptor(keyBytes, initialisationVectorBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                using (var streamReader = new StreamReader(cryptoStream))
                                {
                                    //Console.WriteLine("Decrypted URL: " + streamReader.ReadToEnd(), "INFO");
                                    return streamReader.ReadToEnd();
                                }

                            }
                        }
                    }
                }
            }


        }
    }
}
