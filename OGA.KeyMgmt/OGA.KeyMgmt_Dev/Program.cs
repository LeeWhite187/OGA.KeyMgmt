using OGA.KeyMgmt.Model;
using OGA.KeyMgmt.Store;
using System;
using System.Text;

namespace OGA.KeyMgmt.Dev
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            Generate_Keystore();
        }

        static public void Generate_Keystore()
        {
            // Accept the current encryption key...
            string rtkey = "enter_key_here";


            string storagepassword = rtkey;

            // Create a test key...
            var k1 = new KeyObject_v2();
            k1.KeyName = Guid.NewGuid().ToString();
            k1.KeyType = eKeyType.AES.ToString();
            k1.CreationUTC = DateTime.UtcNow;
            k1.LastUpdateUTC = k1.CreationUTC;
            k1.Status = eKeyStatus.Enabled;
            k1.KeyLength = 256;
            k1.HasPrivateKey = true;
            k1.PrivateKey = Nanoid.Nanoid.Generate( size:32);
            k1.PrivEncrypted = false;
            k1.PublicKey = "";
            k1.HasPublicKey = false;
            k1.IsBase64Encoded = false;
            k1.Uses = Guid.NewGuid().ToString();

            // Add the key to the store...
            var ks = new KeyStore_v2_JsonConfig(storagepassword);
            var res = ks.AddKey_toStore(k1);

            var res2 = ks.Save(out var config);

            string jsonconfig = Newtonsoft.Json.JsonConvert.SerializeObject(config, Newtonsoft.Json.Formatting.Indented);

            int x = 0;
        }
    }
}
