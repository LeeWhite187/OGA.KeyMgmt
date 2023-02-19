using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.KeyMgmt.Config;

namespace NETCore_Common_Tests
{
    [TestClass]
    public class KeyStore_Config_Tests
    {
        [TestMethod]
        public void TestMethod01()
        {
            var cfg = new KeyStore_StorageStruct();
            cfg.CreationDateUTC = DateTime.UtcNow;
            cfg.LastUpdateUTC = DateTime.UtcNow;
            
            cfg.Storage_Algo = Guid.NewGuid().ToString();
            cfg.Storage_KeyId = Guid.NewGuid().ToString();
            cfg.Signing_Algo = Guid.NewGuid().ToString();
            
            cfg.DataVersion = new Nanoid.CryptoRandom().Next(1000);
            cfg.KeystoreVersion = new Nanoid.CryptoRandom().Next(1000);
            cfg.StructVersion = new Nanoid.CryptoRandom().Next(1000);

            cfg.KeyData = Guid.NewGuid().ToString();
            cfg.Signature = Guid.NewGuid().ToString();

            if (cfg == null)
                Assert.Fail("Not created");
        }

        [TestMethod]
        public void TestMethod02()
        {
            var cfg = new KeyStore_StorageStruct();
            cfg.CreationDateUTC = DateTime.UtcNow;
            cfg.LastUpdateUTC = DateTime.UtcNow;
            
            cfg.Storage_Algo = Guid.NewGuid().ToString();
            cfg.Storage_KeyId = Guid.NewGuid().ToString();
            cfg.Signing_Algo = Guid.NewGuid().ToString();
            
            cfg.DataVersion = new Nanoid.CryptoRandom().Next(1000);
            cfg.KeystoreVersion = new Nanoid.CryptoRandom().Next(1000);
            cfg.StructVersion = new Nanoid.CryptoRandom().Next(1000);

            cfg.KeyData = Guid.NewGuid().ToString();
            cfg.Signature = Guid.NewGuid().ToString();

            if (cfg == null)
                Assert.Fail("Not created");

            // Serialize the config...
            var jsonstring = Newtonsoft.Json.JsonConvert.SerializeObject(cfg);

            var cfg2 = Newtonsoft.Json.JsonConvert.DeserializeObject<KeyStore_StorageStruct>(jsonstring);

            if (cfg2 == null)
                Assert.Fail("Not created");

            if (cfg.CreationDateUTC != cfg2.CreationDateUTC)
                Assert.Fail("Not created");
            if (cfg.LastUpdateUTC != cfg2.LastUpdateUTC)
                Assert.Fail("Not created");

            if (cfg.Storage_Algo != cfg2.Storage_Algo)
                Assert.Fail("Not created");
            if (cfg.Storage_KeyId != cfg2.Storage_KeyId)
                Assert.Fail("Not created");
            if (cfg.Signing_Algo != cfg2.Signing_Algo)
                Assert.Fail("Not created");

            if (cfg.DataVersion != cfg2.DataVersion)
                Assert.Fail("Not created");
            if (cfg.KeystoreVersion != cfg2.KeystoreVersion)
                Assert.Fail("Not created");
            if (cfg.StructVersion != cfg2.StructVersion)
                Assert.Fail("Not created");

            if (cfg.KeyData != cfg2.KeyData)
                Assert.Fail("Not created");
            if (cfg.Signature != cfg2.Signature)
                Assert.Fail("Not created");
        }
    }
}
