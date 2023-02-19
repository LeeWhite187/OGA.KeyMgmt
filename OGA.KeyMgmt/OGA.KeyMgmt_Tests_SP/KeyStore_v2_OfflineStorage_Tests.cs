using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.KeyMgmt.Config;
using OGA.KeyMgmt.Model;
using OGA.KeyMgmt.Store;

namespace NETCore_Common_Tests
{
    /// <summary>
    /// Couple of tests to confirm reliable storage and retrieval of keystore.
    /// </summary>
    [TestClass]
    public class KeyStore_v2_OfflineStorage_Tests
    {
        // Test 1  Create two keys, add both to the store. Save the store.
        //          Load the store from disk, delete the first key, and save the store again.
        //          Load the updated store from disk.
        //          Verify only the second key remains.
        [TestMethod]
        public void Test1()
        {
            // Create a surrogate storage key...
            var res = KeyStore_v2_Base.Create_New_AES_Key("storage", 256, out var storagekey);
            if (res != 1)
                Assert.Fail("Failed to create storage key.");


            // Get a testing folder...
            string testfolder = "C:\\Testing";
            // Create a store filename...
            string store_filename = "keystore-" + Guid.NewGuid().ToString();
            // Create a store path...
            string store_filepath = System.IO.Path.Combine(testfolder, store_filename);

            // Create a couple of test keys that we will store...
            var res2 = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);
            if (res2 != 1)
                Assert.Fail("Failed to create key.");
            var res3 = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k3);
            if (res3 != 1)
                Assert.Fail("Failed to create key.");

            // Create a key store, and add the keys to it...
            var ks1 = new KeyStore_v2_File(store_filepath, storagekey);
            var ks1res2 = ks1.AddKey_toStore(k2);
            if (ks1res2 != 1)
                Assert.Fail("Failed to create key.");
            var ks1res3 = ks1.AddKey_toStore(k3);
            if (ks1res3 != 1)
                Assert.Fail("Failed to create key.");

            // Save the keystore...
            var ks1save = ks1.Save();
            if (ks1save != 1)
                Assert.Fail("Failed to save keystore.");

            // Create a new storage key instance...
            var res444 = KeyStore_v2_Base.Create_New_AES_Key("storage", 256, out var storagekey2);
            if(res444 != 1)
                Assert.Fail("Failed to create second storage key.");
            // Override the storage key data...
            storagekey2.PrivateKey = storagekey.PrivateKey;

            // Attempt to load the keystore file into a new keystore instance...
            var ks2 = new KeyStore_v2_File(store_filepath, storagekey2);
            var res5 = ks2.Load();
            if(res5 != 1)
                Assert.Fail("Failed to load keystore with second storage key.");

            // Massage the file data into the format we will use for a config.json file...

            // Read in the raw file data...
            var rawtext = System.IO.File.ReadAllText(store_filepath);

            StringBuilder b = new StringBuilder();
            b.AppendLine("{");
            b.Append("  \"Keystore\": ");
            b.Append(rawtext);
            b.AppendLine("");
            b.AppendLine("}");

            // Create a filename for the new file...
            string file2 = Guid.NewGuid().ToString() + ".json";

            // Save the modified file data...
            System.IO.File.WriteAllText(System.IO.Path.Combine(testfolder, file2), b.ToString());

            // Retrieve our configuration section, the same way that NET Core config builder startup would...
            IConfigurationSection keystoresection;
            {
                // Create a file provider that lets us specify the folder where we will look for configuration...
                var fp = new PhysicalFileProvider(testfolder);

                // Start a config builder that will load our test config file...
                var config = new ConfigurationBuilder()
                    // Have it load our test config file...
                    .AddJsonFile(fp, file2, false, true)
                    .AddEnvironmentVariables()
                    // Tell it to build, so we can use the collected config data...
                    .Build();

                // Retrieve the configuration section we need...
                keystoresection = config.GetSection("Keystore");
            }

            // Hydrate the config data to our POCO...
            KeyStore_StorageStruct keystoreconfig = keystoresection.Get<KeyStore_StorageStruct>();
            // Fix any DateTimes, because NET Core config builder doesn't preserve UTC on load...
            keystoreconfig.LastUpdateUTC = keystoreconfig.LastUpdateUTC.ToUniversalTime();
            keystoreconfig.CreationDateUTC = keystoreconfig.CreationDateUTC.ToUniversalTime();

            // Now, we need to attempt to load a keystore, the same way that the NET Core startup would...
            KeyStore_v2_JsonConfig ks;
            {
                // Create a key store with our runtime encryption key as the storage key...
                KeyStore_v2_Base.Create_New_AES_Key("storage", 256, out var k);
                k.PrivateKey = storagekey.PrivateKey;

                ks = new KeyStore_v2_JsonConfig(k);

                // Load the keystore config...
                var ksres = ks.Load(keystoreconfig);
                if(ksres != 1)
                // Keystore failed to load, so we will throw.
                    throw new Exception("Startup:ConfigureServices: Keystore failed to load config.");
            }

            // The above should have thrown if the keystore config failed to validate.
            // If we are here, it passed.
            int x = 0;
        }
    }
}
