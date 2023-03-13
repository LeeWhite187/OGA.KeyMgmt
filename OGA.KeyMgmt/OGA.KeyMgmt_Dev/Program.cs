using OGA.KeyMgmt.Config;
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

            var jsonstring = Generate_Keystore();

            Verify_Keystore_Instance(jsonstring);
        }

        static public string Generate_Keystore()
        {
            // Accept the current encryption key...
            string rtkey = "";

            // Create a key store with our runtime encryption key as the storage key...
            KeyStore_v2_Base.Create_New_AES_Key("storage", 256, out var k);
            k.PrivateKey = rtkey;

            var ks = new KeyStore_v2_JsonConfig(k);

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
            var res = ks.AddKey_toStore(k1);

            var res2 = ks.Save(out var config);

            string jsonconfig = Newtonsoft.Json.JsonConvert.SerializeObject(config, Newtonsoft.Json.Formatting.Indented);

            return jsonconfig;
        }

        static private void Verify_Keystore_Instance(string jsonstring)
        {
            // Accept the current encryption key...
            string rtkey = "";

            // Create a key store with our runtime encryption key as the storage key...
            KeyStore_v2_Base.Create_New_AES_Key("storage", 256, out var k);
            k.PrivateKey = rtkey;

            var ks = new KeyStore_v2_JsonConfig(k);

            // Deserialize the json config of the keystore data...
            var ksconfig = Newtonsoft.Json.JsonConvert.DeserializeObject<KeyStore_StorageStruct>(jsonstring);

            // Have the keystore load the json config...
            var res = ks.Load(ksconfig);

            int x = 0;
        }
    }
}
