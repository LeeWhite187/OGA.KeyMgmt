using System;
using System.Text;

namespace OGA.KeyMgmt.Helper
{
    /// <summary>
    /// Adapted from 
    /// </summary>
    public class AES256Crypto
    {
        //While an app specific salt is not the best practice for
        //password based encryption, it's probably safe enough as long as
        //it is truly uncommon. Also too much work to alter this answer otherwise.
        private static byte[] _saltbytes;
        static private string salt = "salted value";

        static AES256Crypto()
        {
            _saltbytes = ASCIIEncoding.ASCII.GetBytes(salt);
        }

        /// <summary>
        /// Encrypt the given string using AES.  The string can be decrypted using 
        /// DecryptStringAES().  The sharedSecret parameters must match.
        /// </summary>
        /// <param name="plainText">The text to encrypt.</param>
        /// <param name="sharedSecret">A password used to generate a key for encryption.</param>
        static public string EncryptStringAES(string plainText, string sharedSecret)
        {
            string escapedincoming = (plainText ?? "") + "";
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            // Encrypted string to return
            string outStr = null;
            // RijndaelManaged object used to encrypt the data.
            System.Security.Cryptography.RijndaelManaged aesAlg = null;

            try
            {
                // generate the key from the shared secret and the salt
                System.Security.Cryptography.Rfc2898DeriveBytes key = new System.Security.Cryptography.Rfc2898DeriveBytes(sharedSecret, _saltbytes);

                // Create a RijndaelManaged object
                aesAlg = new System.Security.Cryptography.RijndaelManaged();

                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                // Create a decryptor to perform the stream transform.
                System.Security.Cryptography.ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (System.IO.MemoryStream msEncrypt = new System.IO.MemoryStream())
                {
                    // prepend the IV
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));

                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                    using (System.Security.Cryptography.CryptoStream csEncrypt =
                        new System.Security.Cryptography.CryptoStream(msEncrypt, encryptor, System.Security.Cryptography.CryptoStreamMode.Write))
                    {
                        using (System.IO.StreamWriter swEncrypt = new System.IO.StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(escapedincoming);
                        }
                    }

                    outStr = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                try { aesAlg?.Clear(); } catch (Exception) { }
                try { aesAlg?.Dispose(); } catch (Exception) { }
            }

            // Return the encrypted bytes from the memory stream.
            return outStr;
        }

        /// <summary>
        /// Decrypt the given string.  Assumes the string was encrypted using 
        /// EncryptStringAES(), using an identical sharedSecret.
        /// </summary>
        /// <param name="cipherText">The text to decrypt.</param>
        /// <param name="sharedSecret">A password used to generate a key for decryption.</param>
        static public string DecryptStringAES(string cipherText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("cipherText");

            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            // Declare the RijndaelManaged object
            // used to decrypt the data.
            System.Security.Cryptography.RijndaelManaged aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            try
            {
                // generate the key from the shared secret and the salt
                System.Security.Cryptography.Rfc2898DeriveBytes key = new System.Security.Cryptography.Rfc2898DeriveBytes(sharedSecret, _saltbytes);

                // Create the streams used for decryption.                
                byte[] bytes = Convert.FromBase64String(cipherText);

                using (System.IO.MemoryStream msDecrypt = new System.IO.MemoryStream(bytes))
                {
                    // Create a RijndaelManaged object with the specified key and IV.
                    aesAlg = new System.Security.Cryptography.RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                    // Get the initialization vector from the encrypted stream
                    aesAlg.IV = ReadByteArray(msDecrypt);

                    // Create a decrytor to perform the stream transform.
                    System.Security.Cryptography.ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    using (System.Security.Cryptography.CryptoStream csDecrypt =
                        new System.Security.Cryptography.CryptoStream(msDecrypt, decryptor, System.Security.Cryptography.CryptoStreamMode.Read))
                    {
                        using (System.IO.StreamReader srDecrypt = new System.IO.StreamReader(csDecrypt))

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                try { aesAlg?.Clear(); } catch (Exception) { }
                try { aesAlg?.Dispose(); } catch (Exception) { }
            }

            return plaintext;
        }

        static private byte[] ReadByteArray(System.IO.Stream s)
        {
            byte[] rawLength = new byte[sizeof(int)];

            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];

            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }
    }
}
