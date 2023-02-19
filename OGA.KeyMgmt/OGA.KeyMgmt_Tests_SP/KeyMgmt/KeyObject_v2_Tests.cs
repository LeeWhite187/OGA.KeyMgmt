using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.KeyMgmt.Model;

namespace NETCore_Common_Tests
{
    [TestClass]
    public class KeyObject_v2_Tests
    {
        // Test  1  Simple construction of KeyObject v2.
        //          Was constructed without exception.
        [TestMethod]
        public void Test01()
        {
            var k = new KeyObject_v2();
            k.Status = eKeyStatus.Enabled;
            k.PublicKey = Guid.NewGuid().ToString();
            k.PrivEncrypted = false;
            k.PrivateKey = Guid.NewGuid().ToString();
            k.LastUpdateUTC = DateTime.UtcNow;
            k.KeyType = Guid.NewGuid().ToString();
            k.KeyName = Guid.NewGuid().ToString();
            k.KeyLength = 32;
            k.HasPublicKey = true;
            k.HasPrivateKey = true;
            k.CreationUTC = DateTime.UtcNow.AddDays(1);
            k.Uses = Guid.NewGuid().ToString();
            k.IsBase64Encoded = false;
        }

        // Test  2  Call the Get_KeyStatus_from_String method with a blank string.
        //          Ensure it returns Unknown status.
        [TestMethod]
        public void Test02()
        {
            var f = KeyObject_v2.Get_KeyStatus_from_String("");

            if (f != eKeyStatus.Unknown)
                Assert.Fail("Failed");
        }
        // Test  3  Call the Get_KeyStatus_from_String method with a Enabled string.
        //          Ensure it returns Enabled status.
        [TestMethod]
        public void Test03()
        {
            var f = KeyObject_v2.Get_KeyStatus_from_String("Enabled");

            if (f != eKeyStatus.Enabled)
                Assert.Fail("Failed");
        }
        // Test  4  Call the Get_KeyStatus_from_String method with a Disabled string.
        //          Ensure it returns Disabled status.
        [TestMethod]
        public void Test04()
        {
            var f = KeyObject_v2.Get_KeyStatus_from_String("Disabled");

            if (f != eKeyStatus.Disabled)
                Assert.Fail("Failed");
        }
        // Test  5  Call the Get_KeyStatus_from_String method with a Unknown string.
        //          Ensure it returns Unknown status.
        [TestMethod]
        public void Test05()
        {
            var f = KeyObject_v2.Get_KeyStatus_from_String("Unknown");

            if (f != eKeyStatus.Unknown)
                Assert.Fail("Failed");
        }


        // Test  6  Call the Get_KeyType_from_String method with a blank string.
        //          Ensure it returns Unknown type.
        [TestMethod]
        public void Test06()
        {
            var f = KeyObject_v2.Get_KeyType_from_String("");

            if (f != eKeyType.Unknown)
                Assert.Fail("Failed");
        }
        // Test  7  Call the Get_KeyType_from_String method with a Unknown string.
        //          Ensure it returns Unknown type.
        [TestMethod]
        public void Test07()
        {
            var f = KeyObject_v2.Get_KeyType_from_String("RSA");

            if (f != eKeyType.RSA)
                Assert.Fail("Failed");
        }
        // Test  8  Call the Get_KeyType_from_String method with a ECDH string.
        //          Ensure it returns Unknown type.
        [TestMethod]
        public void Test08()
        {
            var f = KeyObject_v2.Get_KeyType_from_String("ECDH");

            if (f != eKeyType.Unknown)
                Assert.Fail("Failed");
        }
        // Test  9  Call the Get_KeyType_from_String method with a Unknown string.
        //          Ensure it returns Unknown type.
        [TestMethod]
        public void Test09()
        {
            var f = KeyObject_v2.Get_KeyType_from_String("ECDSA");

            if (f != eKeyType.ECDSA)
                Assert.Fail("Failed");
        }
        // Test 10  Call the Get_KeyType_from_String method with a Unknown string.
        //          Ensure it returns Unknown type.
        [TestMethod]
        public void Test10()
        {
            var f = KeyObject_v2.Get_KeyType_from_String("AES");

            if (f != eKeyType.AES)
                Assert.Fail("Failed");
        }
        // Test 10a Call the Get_KeyType_from_String method with a Password string.
        //          Ensure it returns Password type.
        [TestMethod]
        public void Test10a()
        {
            var f = KeyObject_v2.Get_KeyType_from_String("Password");

            if (f != eKeyType.Password)
                Assert.Fail("Failed");
        }
        // Test 11  Call the Get_KeyType_from_String method with a Unknown string.
        //          Ensure it returns Unknown type.
        [TestMethod]
        public void Test11()
        {
            var f = KeyObject_v2.Get_KeyType_from_String("Unknown");

            if (f != eKeyType.Unknown)
                Assert.Fail("Failed");
        }

        // Test 12  Create a key instance, and attempt to copy it without key data.
        //          The copy should be missing its key data.
        [TestMethod]
        public void Test12()
        {
            var k = new KeyObject_v2();
            k.Status = eKeyStatus.Enabled;
            k.PublicKey = Guid.NewGuid().ToString();
            k.PrivEncrypted = false;
            k.PrivateKey = Guid.NewGuid().ToString();
            k.LastUpdateUTC = DateTime.UtcNow;
            k.KeyType = Guid.NewGuid().ToString();
            k.KeyName = Guid.NewGuid().ToString();
            k.KeyLength = 32;
            k.HasPublicKey = true;
            k.HasPrivateKey = true;
            k.CreationUTC = DateTime.UtcNow.AddDays(1);
            k.Uses = Guid.NewGuid().ToString();
            k.IsBase64Encoded = true;

            var k2 = new KeyObject_v2();

            k.CopyTo_withoutKeyData(k2);

            if (k.Status != k2.Status)
                Assert.Fail("Failure");
            if (k.PublicKey == k2.PublicKey)
                Assert.Fail("Failure");
            if (k.PrivEncrypted != k2.PrivEncrypted)
                Assert.Fail("Failure");
            if (k.PrivateKey == k2.PrivateKey)
                Assert.Fail("Failure");
            if (k.LastUpdateUTC != k2.LastUpdateUTC)
                Assert.Fail("Failure");
            if (k.KeyType != k2.KeyType)
                Assert.Fail("Failure");
            if (k.KeyName != k2.KeyName)
                Assert.Fail("Failure");
            if (k.KeyLength != k2.KeyLength)
                Assert.Fail("Failure");
            if (k.HasPublicKey != k2.HasPublicKey)
                Assert.Fail("Failure");
            if (k.HasPrivateKey != k2.HasPrivateKey)
                Assert.Fail("Failure");
            if (k.CreationUTC != k2.CreationUTC)
                Assert.Fail("Failure");
            if (k.Uses != k2.Uses)
                Assert.Fail("Failure");
            if (k2.IsBase64Encoded != false)
                Assert.Fail("Failure");
        }

        // Test 13  Create a key instance, and attempt to copy it without private key data.
        //          The copy should be missing its private key data.
        [TestMethod]
        public void Test13()
        {
            var k = new KeyObject_v2();
            k.Status = eKeyStatus.Enabled;
            k.PublicKey = Guid.NewGuid().ToString();
            k.PrivEncrypted = false;
            k.PrivateKey = Guid.NewGuid().ToString();
            k.LastUpdateUTC = DateTime.UtcNow;
            k.KeyType = Guid.NewGuid().ToString();
            k.KeyName = Guid.NewGuid().ToString();
            k.KeyLength = 32;
            k.HasPublicKey = true;
            k.HasPrivateKey = true;
            k.CreationUTC = DateTime.UtcNow.AddDays(1);
            k.Uses = Guid.NewGuid().ToString();
            k.IsBase64Encoded = true;

            var k2 = new KeyObject_v2();

            k.CopyTo_withoutPrivateData(k2);

            if (k.Status != k2.Status)
                Assert.Fail("Failure");
            if (k.PublicKey != k2.PublicKey)
                Assert.Fail("Failure");
            if (k.PrivEncrypted != k2.PrivEncrypted)
                Assert.Fail("Failure");
            if (k.PrivateKey == k2.PrivateKey)
                Assert.Fail("Failure");
            if (k.LastUpdateUTC != k2.LastUpdateUTC)
                Assert.Fail("Failure");
            if (k.KeyType != k2.KeyType)
                Assert.Fail("Failure");
            if (k.KeyName != k2.KeyName)
                Assert.Fail("Failure");
            if (k.KeyLength != k2.KeyLength)
                Assert.Fail("Failure");
            if (k.HasPublicKey != k2.HasPublicKey)
                Assert.Fail("Failure");
            if (k.HasPrivateKey != k2.HasPrivateKey)
                Assert.Fail("Failure");
            if (k.CreationUTC != k2.CreationUTC)
                Assert.Fail("Failure");
            if (k.Uses != k2.Uses)
                Assert.Fail("Failure");
            if (k2.IsBase64Encoded != true)
                Assert.Fail("Failure");
        }

        // Test 14  Create a key instance, and attempt to copy it with key data.
        //          The copy should have its private and public key data.
        [TestMethod]
        public void Test14()
        {
            var k = new KeyObject_v2();
            k.Status = eKeyStatus.Enabled;
            k.PublicKey = Guid.NewGuid().ToString();
            k.PrivEncrypted = false;
            k.PrivateKey = Guid.NewGuid().ToString();
            k.LastUpdateUTC = DateTime.UtcNow;
            k.KeyType = Guid.NewGuid().ToString();
            k.KeyName = Guid.NewGuid().ToString();
            k.KeyLength = 32;
            k.HasPublicKey = true;
            k.HasPrivateKey = true;
            k.CreationUTC = DateTime.UtcNow.AddDays(1);
            k.Uses = Guid.NewGuid().ToString();
            k.IsBase64Encoded = true;

            var k2 = new KeyObject_v2();

            k.CopyTo_withKeyData(k2);

            if (k.Status != k2.Status)
                Assert.Fail("Failure");
            if (k.PublicKey != k2.PublicKey)
                Assert.Fail("Failure");
            if (k.PrivEncrypted != k2.PrivEncrypted)
                Assert.Fail("Failure");
            if (k.PrivateKey != k2.PrivateKey)
                Assert.Fail("Failure");
            if (k.LastUpdateUTC != k2.LastUpdateUTC)
                Assert.Fail("Failure");
            if (k.KeyType != k2.KeyType)
                Assert.Fail("Failure");
            if (k.KeyName != k2.KeyName)
                Assert.Fail("Failure");
            if (k.KeyLength != k2.KeyLength)
                Assert.Fail("Failure");
            if (k.HasPublicKey != k2.HasPublicKey)
                Assert.Fail("Failure");
            if (k.HasPrivateKey != k2.HasPrivateKey)
                Assert.Fail("Failure");
            if (k.CreationUTC != k2.CreationUTC)
                Assert.Fail("Failure");
            if (k.Uses != k2.Uses)
                Assert.Fail("Failure");
            if (k2.IsBase64Encoded != true)
                Assert.Fail("Failure");
        }

        // Test 15  Create a key instance, and serialize it to a copy.
        //          The copy should be identical.
        [TestMethod]
        public void Test15()
        {
            var k = new KeyObject_v2();
            k.Status = eKeyStatus.Enabled;
            k.PublicKey = Guid.NewGuid().ToString();
            k.PrivEncrypted = false;
            k.PrivateKey = Guid.NewGuid().ToString();
            k.LastUpdateUTC = DateTime.UtcNow;
            k.KeyType = Guid.NewGuid().ToString();
            k.KeyName = Guid.NewGuid().ToString();
            k.KeyLength = 32;
            k.HasPublicKey = true;
            k.HasPrivateKey = true;
            k.CreationUTC = DateTime.UtcNow.AddDays(1);
            k.Uses = Guid.NewGuid().ToString();
            k.IsBase64Encoded = true;

            // Serialize the key...
            var jsonstring = Newtonsoft.Json.JsonConvert.SerializeObject(k);

            // Now, deserialize the key...
            var k2 = Newtonsoft.Json.JsonConvert.DeserializeObject<KeyObject_v2>(jsonstring);

            if (k.Status != k2.Status)
                Assert.Fail("Failure");
            if (k.PublicKey != k2.PublicKey)
                Assert.Fail("Failure");
            if (k.PrivEncrypted != k2.PrivEncrypted)
                Assert.Fail("Failure");
            if (k.PrivateKey != k2.PrivateKey)
                Assert.Fail("Failure");
            if (k.LastUpdateUTC != k2.LastUpdateUTC)
                Assert.Fail("Failure");
            if (k.KeyType != k2.KeyType)
                Assert.Fail("Failure");
            if (k.KeyName != k2.KeyName)
                Assert.Fail("Failure");
            if (k.KeyLength != k2.KeyLength)
                Assert.Fail("Failure");
            if (k.HasPublicKey != k2.HasPublicKey)
                Assert.Fail("Failure");
            if (k.HasPrivateKey != k2.HasPrivateKey)
                Assert.Fail("Failure");
            if (k.CreationUTC != k2.CreationUTC)
                Assert.Fail("Failure");
            if (k.Uses != k2.Uses)
                Assert.Fail("Failure");
            if (k.IsBase64Encoded != k2.IsBase64Encoded)
                Assert.Fail("Failure");
        }

        // Test 16  Create an instance of each symmetric key type.
        //          Check that each reports to be symmetric.
        [TestMethod]
        public void Test16()
        {
            var k1 = new KeyObject_v2();
            k1.KeyType = eKeyType.AES.ToString();

            if (k1.Is_SymmetricKey() == false)
                Assert.Fail("Failure");

            var k2 = new KeyObject_v2();
            k2.KeyType = eKeyType.Password.ToString();

            if (k2.Is_SymmetricKey() == false)
                Assert.Fail("Failure");
        }

        // Test 17  Create an instance of each asymmetric key type.
        //          Check that each reports to NOT be symmetric.
        [TestMethod]
        public void Test17()
        {
            var k1 = new KeyObject_v2();
            k1.KeyType = eKeyType.RSA.ToString();

            if (k1.Is_SymmetricKey() == true)
                Assert.Fail("Failure");

            var k2 = new KeyObject_v2();
            k2.KeyType = eKeyType.ECDSA.ToString();

            if (k2.Is_SymmetricKey() == true)
                Assert.Fail("Failure");

            var k3 = new KeyObject_v2();
            k3.KeyType = eKeyType.Unknown.ToString();

            if (k3.Is_SymmetricKey() == true)
                Assert.Fail("Failure");
        }
    }
}