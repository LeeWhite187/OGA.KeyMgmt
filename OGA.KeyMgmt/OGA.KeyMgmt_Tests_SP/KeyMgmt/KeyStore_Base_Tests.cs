﻿using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.DomainBase.QueryHelpers;
using OGA.KeyMgmt.Model;
using OGA.KeyMgmt.Store;

namespace NETCore_Common_Tests
{
    [TestClass]
    public class KeyStore_Base_Tests
    {
        // Test  1  Simple construction of KeyStore Base v2.
        //          Was constructed without exception.
        [TestMethod]
        public void Test01()
        {
            var ks = new KeyStore_v2_Base();

            if (ks.KeyCount != 0)
                Assert.Fail("Instance is not correct.");
            if (ks.KeyStoreType != "Base")
                Assert.Fail("Instance is not correct.");
            if (ks.KeyStoreVersion != 2)
                Assert.Fail("Instance is not correct.");
        }

        // Test  3  Create a simple AES key and add it to the store.
        //          Check that the key was added.
        [TestMethod]
        public void Test03()
        {
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
            k1.Uses = Guid.NewGuid().ToString();
            k1.IsBase64Encoded = true;

            // Add the key to the store...
            var ks = new KeyStore_v2_Base();
            var res = ks.AddKey_toStore(k1);

            if(ks.HasKey_inStore(k1.KeyName) == false)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(Guid.NewGuid().ToString()) == true)
                Assert.Fail("Instance is not correct.");

            if(res != 1)
                Assert.Fail("Instance is not correct.");

            if (ks.KeyCount != 1)
                Assert.Fail("Instance is not correct.");
        }

        // Test  4  Create two keys and add them to the store.
        //          Check that both keys were added.
        [TestMethod]
        public void Test04()
        {
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
            k1.Uses = Guid.NewGuid().ToString();
            k1.IsBase64Encoded = true;

            // Create a test key...
            var k2 = new KeyObject_v2();
            k2.KeyName = Guid.NewGuid().ToString();
            k2.KeyType = eKeyType.AES.ToString();
            k2.CreationUTC = DateTime.UtcNow;
            k2.LastUpdateUTC = k1.CreationUTC;
            k2.Status = eKeyStatus.Enabled;
            k2.KeyLength = 256;
            k2.HasPrivateKey = true;
            k2.PrivateKey = Nanoid.Nanoid.Generate( size:32);
            k2.PrivEncrypted = false;
            k2.PublicKey = "";
            k2.HasPublicKey = false;
            k2.Uses = Guid.NewGuid().ToString();
            k2.IsBase64Encoded = true;

            // Add both keys to the store...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);
            var res2 = ks.AddKey_toStore(k2);

            if(res1 != 1)
                Assert.Fail("Instance is not correct.");
            if(res2 != 1)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(Guid.NewGuid().ToString()) == true)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(k1.KeyName) == false)
                Assert.Fail("Instance is not correct.");
            if(ks.HasKey_inStore(k2.KeyName) == false)
                Assert.Fail("Instance is not correct.");

            if (ks.KeyCount != 2)
                Assert.Fail("Instance is not correct.");
        }

        // Test  5  Create two keys and add them to the store. Remove the first key by name.
        //          Check that the second key remains.
        [TestMethod]
        public void Test05()
        {
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
            k1.Uses = Guid.NewGuid().ToString();
            k1.IsBase64Encoded = true;

            // Create a test key...
            var k2 = new KeyObject_v2();
            k2.KeyName = Guid.NewGuid().ToString();
            k2.KeyType = eKeyType.AES.ToString();
            k2.CreationUTC = DateTime.UtcNow;
            k2.LastUpdateUTC = k1.CreationUTC;
            k2.Status = eKeyStatus.Enabled;
            k2.KeyLength = 256;
            k2.HasPrivateKey = true;
            k2.PrivateKey = Nanoid.Nanoid.Generate( size:32);
            k2.PrivEncrypted = false;
            k2.PublicKey = "";
            k2.HasPublicKey = false;
            k2.Uses = Guid.NewGuid().ToString();
            k2.IsBase64Encoded = true;

            // Add both keys to the store...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);
            var res2 = ks.AddKey_toStore(k2);

            if(res1 != 1)
                Assert.Fail("Instance is not correct.");
            if(res2 != 1)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(Guid.NewGuid().ToString()) == true)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(k1.KeyName) == false)
                Assert.Fail("Instance is not correct.");
            if(ks.HasKey_inStore(k2.KeyName) == false)
                Assert.Fail("Instance is not correct.");

            if (ks.KeyCount != 2)
                Assert.Fail("Instance is not correct.");

            // Remove the first key from the store...
            ks.RemoveKey_fromStore(k1.KeyName);

            // Check that only the second key remains...
            if(ks.HasKey_inStore(k1.KeyName) == true)
                Assert.Fail("Instance is not correct.");
            if(ks.HasKey_inStore(k2.KeyName) == false)
                Assert.Fail("Instance is not correct.");

            if (ks.KeyCount != 1)
                Assert.Fail("Instance is not correct.");
        }

        // Test  6  Create two keys and add them to the store. Remove the first key by key instance.
        //          Check that the second key remains.
        [TestMethod]
        public void Test06()
        {
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
            k1.Uses = Guid.NewGuid().ToString();
            k1.IsBase64Encoded = true;

            // Create a test key...
            var k2 = new KeyObject_v2();
            k2.KeyName = Guid.NewGuid().ToString();
            k2.KeyType = eKeyType.AES.ToString();
            k2.CreationUTC = DateTime.UtcNow;
            k2.LastUpdateUTC = k1.CreationUTC;
            k2.Status = eKeyStatus.Enabled;
            k2.KeyLength = 256;
            k2.HasPrivateKey = true;
            k2.PrivateKey = Nanoid.Nanoid.Generate( size:32);
            k2.PrivEncrypted = false;
            k2.PublicKey = "";
            k2.HasPublicKey = false;
            k2.Uses = Guid.NewGuid().ToString();
            k2.IsBase64Encoded = true;

            // Add both keys to the store...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);
            var res2 = ks.AddKey_toStore(k2);

            if(res1 != 1)
                Assert.Fail("Instance is not correct.");
            if(res2 != 1)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(Guid.NewGuid().ToString()) == true)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(k1.KeyName) == false)
                Assert.Fail("Instance is not correct.");
            if(ks.HasKey_inStore(k2.KeyName) == false)
                Assert.Fail("Instance is not correct.");

            if (ks.KeyCount != 2)
                Assert.Fail("Instance is not correct.");

            // Remove the first key from the store...
            ks.RemoveKey_fromStore(k1);

            // Check that only the second key remains...
            if(ks.HasKey_inStore(k1.KeyName) == true)
                Assert.Fail("Instance is not correct.");
            if(ks.HasKey_inStore(k2.KeyName) == false)
                Assert.Fail("Instance is not correct.");

            if (ks.KeyCount != 1)
                Assert.Fail("Instance is not correct.");
        }

        // Test  7  Create two keys with same name, and attempt to add both to the store.
        //          The second addition should have failed, and the first key should be intact.
        [TestMethod]
        public void Test07()
        {
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
            k1.Uses = Guid.NewGuid().ToString();
            k1.IsBase64Encoded = true;

            // Create a test key...
            var k2 = new KeyObject_v2();
            k2.KeyName = k1.KeyName;
            k2.KeyType = eKeyType.AES.ToString();
            k2.CreationUTC = DateTime.UtcNow;
            k2.LastUpdateUTC = k1.CreationUTC;
            k2.Status = eKeyStatus.Enabled;
            k2.KeyLength = 256;
            k2.HasPrivateKey = true;
            k2.PrivateKey = Nanoid.Nanoid.Generate( size:32);
            k2.PrivEncrypted = false;
            k2.PublicKey = "";
            k2.HasPublicKey = false;
            k2.Uses = Guid.NewGuid().ToString();
            k2.IsBase64Encoded = true;

            // Add both keys to the store...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);

            if(res1 != 1)
                Assert.Fail("Problem with addition.");

            // Attempt to add the second key...
            var res2 = ks.AddKey_toStore(k2);

            if(res2 == 1)
                Assert.Fail("Problem with addition.");

            if (ks.KeyCount != 1)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(k2.KeyName) == false)
                Assert.Fail("Instance is not correct.");
        }

        // Test  8  Create two keys in store, and get the first key from storage.
        //          Check that the retrieved key is correct.
        [TestMethod]
        public void Test08()
        {
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
            k1.Uses = Guid.NewGuid().ToString();
            k1.IsBase64Encoded = true;

            // Create a test key...
            var k2 = new KeyObject_v2();
            k2.KeyName = Guid.NewGuid().ToString();
            k2.KeyType = eKeyType.AES.ToString();
            k2.CreationUTC = DateTime.UtcNow;
            k2.LastUpdateUTC = k1.CreationUTC;
            k2.Status = eKeyStatus.Enabled;
            k2.KeyLength = 256;
            k2.HasPrivateKey = true;
            k2.PrivateKey = Nanoid.Nanoid.Generate( size:32);
            k2.PrivEncrypted = false;
            k2.PublicKey = "";
            k2.HasPublicKey = false;
            k2.Uses = Guid.NewGuid().ToString();
            k2.IsBase64Encoded = true;

            // Add both keys to the store...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);
            // Attempt to add the second key...
            var res2 = ks.AddKey_toStore(k2);
            if(res1 != 1)
                Assert.Fail("Problem with addition.");
            if(res2 != 1)
                Assert.Fail("Problem with addition.");
            if (ks.KeyCount != 2)
                Assert.Fail("Instance is not correct.");

            // Retrieve the key from store...
            var retres = ks.GetKey_fromStore(k1.KeyName, out var k3);

            if(retres != 1)
                Assert.Fail("Instance is not correct.");

            // Check that the retrieved key is the same as the first key...
            if (k1.Status != k3.Status)
                Assert.Fail("Failure");
            if (k1.PublicKey != k3.PublicKey)
                Assert.Fail("Failure");
            if (k1.PrivEncrypted != k3.PrivEncrypted)
                Assert.Fail("Failure");
            if (k1.PrivateKey != k3.PrivateKey)
                Assert.Fail("Failure");
            if (k1.LastUpdateUTC != k3.LastUpdateUTC)
                Assert.Fail("Failure");
            if (k1.KeyType != k3.KeyType)
                Assert.Fail("Failure");
            if (k1.KeyName != k3.KeyName)
                Assert.Fail("Failure");
            if (k1.KeyLength != k3.KeyLength)
                Assert.Fail("Failure");
            if (k1.HasPublicKey != k3.HasPublicKey)
                Assert.Fail("Failure");
            if (k1.HasPrivateKey != k3.HasPrivateKey)
                Assert.Fail("Failure");
            if (k1.CreationUTC != k3.CreationUTC)
                Assert.Fail("Failure");
            if (k1.Uses != k3.Uses)
                Assert.Fail("Failure");
            if (k1.IsBase64Encoded != k3.IsBase64Encoded)
                Assert.Fail("Failure");
        }

        // Test  9  Create a key in store, retrieve it from storage, change it slightly, and update the store with it.
        //          Check that it can be retrieved again with the updated data.
        [TestMethod]
        public void Test09()
        {
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
            k1.Uses = Guid.NewGuid().ToString();
            k1.IsBase64Encoded = true;

            // Add it to the store...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);
            if(res1 != 1)
                Assert.Fail("Problem with addition.");

            // Retrieve the key from store...
            var retres = ks.GetKey_fromStore(k1.KeyName, out var k2);
            if(retres != 1)
                Assert.Fail("Instance is not correct.");

            // Update the key...
            k2.PrivateKey = Guid.NewGuid().ToString();

            // Update the store with the revised key...
            var updres = ks.UpdateKey_inStore(k2);
            if(updres != 1)
                Assert.Fail("Instance is not correct.");

            // Now, retrieve the updated key from the store...
            var retres2 = ks.GetKey_fromStore(k1.KeyName, out var k3);
            if(retres != 1)
                Assert.Fail("Instance is not correct.");

            // Check that the retrieved updated key is the same as the first key...
            if (k1.Status != k3.Status)
                Assert.Fail("Failure");
            if (k1.PublicKey != k3.PublicKey)
                Assert.Fail("Failure");
            if (k1.PrivEncrypted != k3.PrivEncrypted)
                Assert.Fail("Failure");
            if (k2.PrivateKey != k3.PrivateKey)
                Assert.Fail("Failure");
            if (k1.LastUpdateUTC != k3.LastUpdateUTC)
                Assert.Fail("Failure");
            if (k1.KeyType != k3.KeyType)
                Assert.Fail("Failure");
            if (k1.KeyName != k3.KeyName)
                Assert.Fail("Failure");
            if (k1.KeyLength != k3.KeyLength)
                Assert.Fail("Failure");
            if (k1.HasPublicKey != k3.HasPublicKey)
                Assert.Fail("Failure");
            if (k1.HasPrivateKey != k3.HasPrivateKey)
                Assert.Fail("Failure");
            if (k1.CreationUTC != k3.CreationUTC)
                Assert.Fail("Failure");
            if (k1.Uses != k3.Uses)
                Assert.Fail("Failure");
            if (k1.IsBase64Encoded != k3.IsBase64Encoded)
                Assert.Fail("Failure");
        }



        // Test 10  Call the Create AES keypair method.
        //          Verify the key is valid.
        [TestMethod]
        public void Test10()
        {
            string keyname = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_AES_Key(keyname, 256, out var k1);
            if (res != 1)
                Assert.Fail("Failed to create key");

            // Check that the created key is correct...
            if (k1.KeyName != keyname)
                Assert.Fail("Failure");
            if (k1.Status != eKeyStatus.Enabled)
                Assert.Fail("Failure");
            if (k1.PublicKey != "")
                Assert.Fail("Failure");
            if (k1.KeyType != eKeyType.AES.ToString())
                Assert.Fail("Failure");
            if (k1.KeyLength != 256)
                Assert.Fail("Failure");
            if (k1.HasPublicKey == true)
                Assert.Fail("Failure");
            if (k1.PrivEncrypted == true)
                Assert.Fail("Failure");
            if (string.IsNullOrEmpty(k1.PrivateKey))
                Assert.Fail("Failure");
            if (k1.LastUpdateUTC != k1.CreationUTC)
                Assert.Fail("Failure");
            if (k1.HasPrivateKey != true)
                Assert.Fail("Failure");
            if (k1.HasPrivateKey != true)
                Assert.Fail("Failure");
            if (k1.IsBase64Encoded != true)
                Assert.Fail("Failure");
            if (k1.Uses != "")
                Assert.Fail("Failure");
        }

        // Test 12  Call the Create AES keypair method.
        //          Attempt usage, and verify it works.
        [TestMethod]
        public void Test12()
        {
            string keyname = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_AES_Key(keyname, 256, out var k1);
            if (res != 1)
                Assert.Fail("Failed to create key");

            // Create a copy of the key with our password...
            var k2 = new KeyObject_v2();
            k1.CopyTo_withKeyData(k2);
            k2.PrivateKey = k1.PrivateKey;
            k2.PrivEncrypted = false;
            k2.IsBase64Encoded = false;

            // Now, call the verification method...
            var res2 = KeyStore_v2_Base.Verify_AESKey(k2);

            if(res2 != 1)
                Assert.Fail("Failure");
        }
        // Test 13  Call the Create AES keypair method.
        //          Attempt usage, and verify it works.
        [TestMethod]
        public void Test13()
        {
            string keyname = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_AES_Key(keyname, 256, out var k1);
            if (res != 1)
                Assert.Fail("Failed to create key");

            // Now, call the verification method...
            var res2 = KeyStore_v2_Base.Verify_AESKey(k1);

            if(res2 != 1)
                Assert.Fail("Failure");
        }



        // Test 14  Attempt to create an RSA key pair with an udersized RSA key length.
        //          Check that an error was returned.
        [TestMethod]
        public void Test14()
        {
            string keyname = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_RSA_KeyPair(keyname, 511, out var k1);
            if (res != -1)
                Assert.Fail("Expected an error");
        }
        // Test 15  Create an RSA key pair, and call the verification method.
        //          Check that the key works.
        [TestMethod]
        public void Test15()
        {
            string keyname = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_RSA_KeyPair(keyname, 1024, out var k1);
            if (res != 1)
                Assert.Fail("Failed to create key");

            // Now, call the verification method...
            var res2 = KeyStore_v2_Base.Verify_RSAKeyPair(k1);
            if(res2 != 1)
                Assert.Fail("Failure");
        }
        // Test 16  Create an RSA key pair. Attempt usage to ensure we can perform signing and verification.
        //          Check that the key usage worked.
        [TestMethod]
        public void Test16()
        {
            string keyname = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_RSA_KeyPair(keyname, 1024, out var k1);
            if (res != 1)
                Assert.Fail("Failed to create key");

            // Create a candidate string that we will sign and verify...
            var candidate_string = "The quick brown fox jumped over the lazy dog";



            // Attempt to hash the candidate string...
            byte[] candidatebytes = OGA.KeyMgmt.Helper.Conversions.String_to_Byte(candidate_string);
            // Create a hash of the byte array...
            System.Security.Cryptography.SHA1 sec = new System.Security.Cryptography.SHA1CryptoServiceProvider();
            byte[] hashbytes = sec.ComputeHash(candidatebytes);


            // Attempt to sign the hash...
            System.Security.Cryptography.RSACryptoServiceProvider csp_signer = new System.Security.Cryptography.RSACryptoServiceProvider(k1.KeyLength);
            csp_signer.ImportCspBlob(Convert.FromBase64String(k1.PrivateKey));
            byte[] signature = csp_signer.SignHash(hashbytes, System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA1"));


            // Now, do a verification of the signature for the given candidate string...
            System.Security.Cryptography.RSACryptoServiceProvider csp_verifier = new System.Security.Cryptography.RSACryptoServiceProvider(k1.KeyLength);
            csp_verifier.ImportCspBlob(Convert.FromBase64String(k1.PublicKey));
            bool result = csp_verifier.VerifyHash(hashbytes, System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA1"), signature);

            if(result != true)
                Assert.Fail("Failure");
        }
        // Test 17  Create an RSA key pair. Attempt usage to ensure we can perform signing and verification.
        //          Check that the key usage worked.
        [TestMethod]
        public void Test17()
        {
            string keyname = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_RSA_KeyPair(keyname, 1024, out var k1);
            if (res != 1)
                Assert.Fail("Failed to create key");

            // Create a candidate string that we will sign and verify...
            var candidate_string = "The quick brown fox jumped over the lazy dog";


            // Attempt to hash the candidate string...
            byte[] candidatebytes = OGA.KeyMgmt.Helper.Conversions.String_to_Byte(candidate_string);
            // Create a hash of the byte array...
            System.Security.Cryptography.SHA1 sec = new System.Security.Cryptography.SHA1CryptoServiceProvider();
            byte[] hashbytes = sec.ComputeHash(candidatebytes);


            // Attempt to sign the hash...
            System.Security.Cryptography.RSACryptoServiceProvider csp_signer = new System.Security.Cryptography.RSACryptoServiceProvider(k1.KeyLength);
            csp_signer.ImportCspBlob(Convert.FromBase64String(k1.PrivateKey));
            byte[] signature = csp_signer.SignHash(hashbytes, System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA1"));


            // Now, do a verification of the signature for the given candidate string...
            System.Security.Cryptography.RSACryptoServiceProvider csp_verifier = new System.Security.Cryptography.RSACryptoServiceProvider(k1.KeyLength);
            csp_verifier.ImportCspBlob(Convert.FromBase64String(k1.PublicKey));
            bool result = csp_verifier.VerifyHash(hashbytes, System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA1"), signature);

            if(result != true)
                Assert.Fail("Failure");
        }




        // Test 19  Create an ECDSA key pair, and call the verification method.
        //          Check that the key works.
        [TestMethod]
        public void Test19()
        {
            string keyname = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_ECDSA_KeyPair(keyname, out var k1);
            if (res != 1)
                Assert.Fail("Failed to create key");

            // Now, call the verification method...
            var res2 = KeyStore_v2_Base.Verify_ECDSAKeyPair(k1);
            if(res2 != 1)
                Assert.Fail("Failure");
        }
        // Test 20  Create an ECDSA key pair. Attempt usage to ensure we can perform signing and verification.
        //          Check that the key usage worked.
        [TestMethod]
        public void Test20()
        {
            string keyname = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_ECDSA_KeyPair(keyname, out var k1);
            if (res != 1)
                Assert.Fail("Failed to create key");

            // Create a candidate string that we will sign and verify...
            var candidate_string = "The quick brown fox jumped over the lazy dog";

            // Convert the candidate string to a byte array...
            byte[] candidatebytes = OGA.KeyMgmt.Helper.Conversions.String_to_Byte(candidate_string);




            // Create a signing key instance...
            ECDsa eckey_sign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] privkey = Convert.FromBase64String(k1.PrivateKey);
            eckey_sign.ImportECPrivateKey(privkey, out _);


            // Attempt to sign the candidate string...
            byte[] signaturebytes = eckey_sign.SignData(candidatebytes, HashAlgorithmName.SHA256);


            // Create a verification key instance...
            ECDsa eckey_verification = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] pubkey = Convert.FromBase64String(k1.PublicKey);
            eckey_verification.ImportSubjectPublicKeyInfo(pubkey, out _);


            // Now, do a verification of the signature for the given candidate string...
            bool result = eckey_verification.VerifyData(candidatebytes, signaturebytes, HashAlgorithmName.SHA256);

            if(result != true)
                Assert.Fail("Failure");
        }
        // Test 21  Create an ECDSA key pair with a privatekey encryption password. Attempt usage to ensure we can perform signing and verification.
        //          Check that the key usage worked.
        [TestMethod]
        public void Test21()
        {
            string keyname = Guid.NewGuid().ToString();
            string privatekey_encryptionpassword = Guid.NewGuid().ToString();

            // Call the creation method...
            int res = KeyStore_v2_Base.Create_New_ECDSA_KeyPair(keyname, out var k1);
            if (res != 1)
                Assert.Fail("Failed to create key");

            // Create a candidate string that we will sign and verify...
            var candidate_string = "The quick brown fox jumped over the lazy dog";

            // Convert the candidate string to a byte array...
            byte[] candidatebytes = OGA.KeyMgmt.Helper.Conversions.String_to_Byte(candidate_string);



            // Create a signing key instance...
            ECDsa eckey_sign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] privkey = Convert.FromBase64String(k1.PrivateKey);
            eckey_sign.ImportECPrivateKey(privkey, out _);


            // Attempt to sign the candidate string...
            byte[] signaturebytes = eckey_sign.SignData(candidatebytes, HashAlgorithmName.SHA256);



            // Create a verification key instance...
            ECDsa eckey_verification = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] pubkey = Convert.FromBase64String(k1.PublicKey);
            eckey_verification.ImportSubjectPublicKeyInfo(pubkey, out _);



            // Now, do a verification of the signature for the given candidate string...
            bool result = eckey_verification.VerifyData(candidatebytes, signaturebytes, HashAlgorithmName.SHA256);

            if(result != true)
                Assert.Fail("Failure");
        }

        // Test 22  Do a naked EC key creation, then a sign with a new key instance, then a verify with a third new instnace.
        //          Check that the key works.
        [TestMethod]
        public void Test22()
        {
            string keyname = Guid.NewGuid().ToString();

            // Create an ec key instance...
            ECDsa eckey1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var prv = eckey1.ExportECPrivateKey();
            var pub = eckey1.ExportSubjectPublicKeyInfo();

            // Convert the key pair to base64.
            string b64privkey = Convert.ToBase64String(prv);
            string b64pubkey = Convert.ToBase64String(pub);


            // Create a signing key instance...
            ECDsa eckey_sign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] privkey_sign = Convert.FromBase64String(b64privkey);
            eckey_sign.ImportECPrivateKey(privkey_sign, out _);


            // Have it sign some test data...
            string testdata = Guid.NewGuid().ToString();
            byte[] testbytes = OGA.KeyMgmt.Helper.Conversions.String_to_Byte(testdata);

            var signature1 = eckey_sign.SignData(testbytes, HashAlgorithmName.SHA256);



            // Create a verification key instance...
            ECDsa eckey_ver = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] pubkey_ver = Convert.FromBase64String(b64pubkey);
            eckey_ver.ImportSubjectPublicKeyInfo(pubkey_ver, out _);

            // Verify the signature with the second key...
            var res = eckey_ver.VerifyData(testbytes, signature1, HashAlgorithmName.SHA256);
            if (res != true)
                Assert.Fail("Failed to verify key");
        }

        // Test 23  Call the create EC key method, then do a naked sign and verification with it.
        //          Check that the key works.
        [TestMethod]
        public void Test23()
        {
            string keyname = Guid.NewGuid().ToString();

            // Create an ec key instance...
            var res44 = KeyStore_v2_Base.Create_New_ECDSA_KeyPair(keyname, out var k1);




            // Instanciate an eckey for signing...
            ECDsa eckey1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] privkey = Convert.FromBase64String(k1.PrivateKey);
            eckey1.ImportECPrivateKey(privkey, out _);


            // Sign some test data with the key...
            string testdata = Guid.NewGuid().ToString();
            byte[] testbytes = OGA.KeyMgmt.Helper.Conversions.String_to_Byte(testdata);



            var signature1 = eckey1.SignData(testbytes, HashAlgorithmName.SHA256);



            // Create a second eckey instance...
            ECDsa eckey2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] pubkey = Convert.FromBase64String(k1.PublicKey);
            eckey2.ImportSubjectPublicKeyInfo(pubkey, out _);



            // Verify the signature with the second key...
            var res = eckey2.VerifyData(testbytes, signature1, HashAlgorithmName.SHA256);
            if (res != true)
                Assert.Fail("Failed to verify key");
        }

        // Test 40  Create a keystore and verify its creation date.
        [TestMethod]
        public void Test40()
        {
            DateTime currtime = DateTime.UtcNow.AddSeconds(-1);

            var ks = new KeyStore_v2_Base();

            // Get the current time again...
            DateTime currtime2 = DateTime.UtcNow.AddSeconds(1);

            // Check that the keystore was created between the two times...
            if (ks.CreationDateUTC.CompareTo(currtime) < 0)
                Assert.Fail("Instance is not correct.");
            if (ks.CreationDateUTC.CompareTo(currtime2) > 0)
                Assert.Fail("Instance is not correct.");
        }

        // Test 41  Create a keystore and verify its last modified date.
        [TestMethod]
        public void Test41()
        {
            DateTime currtime = DateTime.UtcNow.AddSeconds(-1);

            var ks = new KeyStore_v2_Base();

            // Get the current time again...
            DateTime currtime2 = DateTime.UtcNow.AddSeconds(1);

            // Check that the keystore was created between the two times...
            if (ks.CreationDateUTC.CompareTo(currtime) < 0)
                Assert.Fail("Instance is not correct.");
            if (ks.CreationDateUTC.CompareTo(currtime2) > 0)
                Assert.Fail("Instance is not correct.");
        }

        // Test 42  Create a keystore. Record its last modified date.
        //          Add a key, and verify the last update time changed.
        [TestMethod]
        public void Test42()
        {
            var ks = new KeyStore_v2_Base();

            // Get the current last update time and version...
            var ct = ks.LastUpdateUTC;
            var dataversion = ks.DataVersion;

            System.Threading.Thread.Sleep(20);

            KeyObject_v2 k = null;
            var res = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out k);
            if (res != 1)
                Assert.Fail("Failed");

            System.Threading.Thread.Sleep(1000);

            // Add a key to the store...
            var res2 = ks.AddKey_toStore(k);
            if (res2 != 1)
                Assert.Fail("Failed");

            // Check that the last update time changed...
            if (ks.LastUpdateUTC.CompareTo(ct) == 0)
                Assert.Fail("Instance is not correct.");
            // Check that the last update time changed...
            if (ks.DataVersion != dataversion + 1)
                Assert.Fail("Instance is not correct.");
        }

        // Test 43  Create a keystore with a key in it.
        //          Remove the key, and verify the last update time changed.
        [TestMethod]
        public void Test43()
        {
            DateTime currtime = DateTime.UtcNow;

            var ks = new KeyStore_v2_Base();

            KeyObject_v2 k = null;
            var res = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out k);
            if (res != 1)
                Assert.Fail("Failed");

            // Add a key to the store...
            var res2 = ks.AddKey_toStore(k);
            if (res2 != 1)
                Assert.Fail("Failed");

            // Get the current last update time and version...
            var ct = ks.LastUpdateUTC;
            var dataversion = ks.DataVersion;

            System.Threading.Thread.Sleep(1000);

            // Remove the key from the store...
            ks.RemoveKey_fromStore(k);

            // Check that the last update time changed...
            if (ks.LastUpdateUTC.CompareTo(ct) == 0)
                Assert.Fail("Instance is not correct.");
            // Check that the last update time changed...
            if (ks.DataVersion != dataversion + 1)
                Assert.Fail("Instance is not correct.");
        }

        // Test 44  Create a keystore with a key in it.
        //          Update the key, and verify the last update time changed.
        [TestMethod]
        public void Test44()
        {
            DateTime currtime = DateTime.UtcNow;

            var ks = new KeyStore_v2_Base();

            KeyObject_v2 k = null;
            var res = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out k);
            if (res != 1)
                Assert.Fail("Failed");

            // Add a key to the store...
            var res2 = ks.AddKey_toStore(k);
            if (res2 != 1)
                Assert.Fail("Failed");

            // Get the current last update time and version...
            var ct = ks.LastUpdateUTC;
            var dataversion = ks.DataVersion;

            System.Threading.Thread.Sleep(1000);

            k.KeyLength = 23;

            // Update the key in the store...
            ks.UpdateKey_inStore(k);

            // Check that the last update time changed...
            if (ks.LastUpdateUTC.CompareTo(ct) == 0)
                Assert.Fail("Instance is not correct.");
            // Check that the last update time changed...
            if (ks.DataVersion != dataversion + 1)
                Assert.Fail("Instance is not correct.");
        }

        // Test 45  Create a keystore with a key in it.
        //          Call the update method without changing the key, and verify the last update time stays the same.
        [TestMethod]
        public void Test45()
        {
            DateTime currtime = DateTime.UtcNow;

            var ks = new KeyStore_v2_Base();

            KeyObject_v2 k = null;
            var res = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out k);
            if (res != 1)
                Assert.Fail("Failed");

            // Add a key to the store...
            var res2 = ks.AddKey_toStore(k);
            if (res2 != 1)
                Assert.Fail("Failed");

            // Get the current last update time and version...
            var ct = ks.LastUpdateUTC;
            var dataversion = ks.DataVersion;

            System.Threading.Thread.Sleep(1000);

            // Call update with no change to the key...
            ks.UpdateKey_inStore(k);

            // Check that the last update time did not change...
            if (ks.LastUpdateUTC.CompareTo(ct) != 0)
                Assert.Fail("Instance is not correct.");
            if (ks.DataVersion != dataversion)
                Assert.Fail("Instance is not correct.");
        }

        // Test 50  Create a keystore with three keys (two asymmetric, and one symmetric).
        //          Compose a predicate filter to search for the symmetric key.
        //          Verify the symmetric key is retrieved.
        [TestMethod]
        public void Test50()
        {
            var ks = new KeyStore_v2_Base();

            int res1 = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k1);
            if (res1 != 1)
                Assert.Fail("Wrong");
            int res2 = ks.AddKey_toStore(k1);
            if (res2 != 1)
                Assert.Fail("Wrong");

            int res3 = KeyStore_v2_Base.Create_New_ECDSA_KeyPair(Guid.NewGuid().ToString(), out var k2);
            if (res3 != 1)
                Assert.Fail("Wrong");
            int res4 = ks.AddKey_toStore(k2);
            if (res4 != 1)
                Assert.Fail("Wrong");

            int res5 = KeyStore_v2_Base.Create_New_RSA_KeyPair(Guid.NewGuid().ToString(), 512, out var k3);
            if (res5 != 1)
                Assert.Fail("Wrong");
            int res6 = ks.AddKey_toStore(k3);
            if (res6 != 1)
                Assert.Fail("Wrong");

            // Check that we have three keys...
            if (ks.KeyCount != 3)
                Assert.Fail("Wrong");

            // Now, compose a filter we will test with...
            var filter = OGA.DomainBase.QueryHelpers.PredicateBuilder.True<KeyObject_v2>();

            // Filter for symmetric keys...
            filter = filter.And<KeyObject_v2>(t => t.Is_SymmetricKey());

            // Filter for enabled keys...
            filter = filter.And<KeyObject_v2>(t => t.Status == eKeyStatus.Enabled);

            // Filter for private keys...
            filter = filter.And<KeyObject_v2>(t => t.HasPrivateKey == true);

            var res = ks.GetOldestKey_fromStore_byFilter(filter, out var k4);
            if (res != 1)
                Assert.Fail("Wrong");

            // Check that we found our AES key...
            if (k1.Status != k4.Status)
                Assert.Fail("Failure");
            if (k1.PublicKey != k4.PublicKey)
                Assert.Fail("Failure");
            if (k1.PrivEncrypted != k4.PrivEncrypted)
                Assert.Fail("Failure");
            if (k1.PrivateKey != k4.PrivateKey)
                Assert.Fail("Failure");
            if (k1.LastUpdateUTC != k4.LastUpdateUTC)
                Assert.Fail("Failure");
            if (k1.KeyType != k4.KeyType)
                Assert.Fail("Failure");
            if (k1.KeyName != k4.KeyName)
                Assert.Fail("Failure");
            if (k1.KeyLength != k4.KeyLength)
                Assert.Fail("Failure");
            if (k1.HasPublicKey != k4.HasPublicKey)
                Assert.Fail("Failure");
            if (k1.HasPrivateKey != k4.HasPrivateKey)
                Assert.Fail("Failure");
            if (k1.CreationUTC != k4.CreationUTC)
                Assert.Fail("Failure");
            if (k1.Uses != k4.Uses)
                Assert.Fail("Failure");
            if (k1.IsBase64Encoded != k4.IsBase64Encoded)
                Assert.Fail("Failure");
        }

        // Test 51  Create a keystore with two AES keys.
        //          Compose a predicate filter to search for the oldest key.
        //          Verify the oldest key is retrieved.
        [TestMethod]
        public void Test51()
        {
            var ks = new KeyStore_v2_Base();

            int res1 = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k1);
            if (res1 != 1)
                Assert.Fail("Wrong");
            k1.CreationUTC = k1.CreationUTC.AddDays(-1);
            int res2 = ks.AddKey_toStore(k1);
            if (res2 != 1)
                Assert.Fail("Wrong");

            int res3 = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);
            if (res3 != 1)
                Assert.Fail("Wrong");
            k2.CreationUTC = k2.CreationUTC.AddDays(-2);
            int res4 = ks.AddKey_toStore(k2);
            if (res4 != 1)
                Assert.Fail("Wrong");


            // Check that we have two keys...
            if (ks.KeyCount != 2)
                Assert.Fail("Wrong");

            // Now, compose a filter we will test with...
            var filter = OGA.DomainBase.QueryHelpers.PredicateBuilder.True<KeyObject_v2>();

            // Filter for symmetric keys...
            filter = filter.And<KeyObject_v2>(t => t.Is_SymmetricKey());

            // Filter for enabled keys...
            filter = filter.And<KeyObject_v2>(t => t.Status == eKeyStatus.Enabled);

            // Filter for private keys...
            filter = filter.And<KeyObject_v2>(t => t.HasPrivateKey == true);

            var res = ks.GetOldestKey_fromStore_byFilter(filter, out var k4);
            if (res != 1)
                Assert.Fail("Wrong");

            // Check that we found our AES key...
            if (k2.KeyName != k4.KeyName)
                Assert.Fail("Failure");
        }

        // Test 52  Create a keystore with two AES keys.
        //          Compose a predicate filter to search for the newest key.
        //          Verify the newest key is retrieved.
        [TestMethod]
        public void Test52()
        {
            var ks = new KeyStore_v2_Base();

            int res1 = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k1);
            if (res1 != 1)
                Assert.Fail("Wrong");
            k1.CreationUTC = k1.CreationUTC.AddDays(-1);
            int res2 = ks.AddKey_toStore(k1);
            if (res2 != 1)
                Assert.Fail("Wrong");

            int res3 = KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);
            if (res3 != 1)
                Assert.Fail("Wrong");
            k2.CreationUTC = k2.CreationUTC.AddDays(-2);
            int res4 = ks.AddKey_toStore(k2);
            if (res4 != 1)
                Assert.Fail("Wrong");


            // Check that we have two keys...
            if (ks.KeyCount != 2)
                Assert.Fail("Wrong");

            // Now, compose a filter we will test with...
            var filter = OGA.DomainBase.QueryHelpers.PredicateBuilder.True<KeyObject_v2>();

            // Filter for symmetric keys...
            filter = filter.And<KeyObject_v2>(t => t.Is_SymmetricKey());

            // Filter for enabled keys...
            filter = filter.And<KeyObject_v2>(t => t.Status == eKeyStatus.Enabled);

            // Filter for private keys...
            filter = filter.And<KeyObject_v2>(t => t.HasPrivateKey == true);

            var res = ks.GetNewestKey_fromStore_byFilter(filter, out var k4);
            if (res != 1)
                Assert.Fail("Wrong");

            // Check that we found our AES key...
            if (k1.KeyName != k4.KeyName)
                Assert.Fail("Failure");
        }


        // Test 60  Populate a keystore with keys.
        //          Get the key names of each.
        [TestMethod]
        public void Test60()
        {
            // Create a test key...
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k1);
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);

            // Add both keys to the store...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);
            var res2 = ks.AddKey_toStore(k2);

            if(res1 != 1)
                Assert.Fail("Instance is not correct.");
            if(res2 != 1)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(k1.KeyName) == false)
                Assert.Fail("Instance is not correct.");
            if(ks.HasKey_inStore(k2.KeyName) == false)
                Assert.Fail("Instance is not correct.");
            if (ks.KeyCount != 2)
                Assert.Fail("Instance is not correct.");

            // Get the keynames list...
            var knl = ks.GetKeyNames_fromStore(null);

            if(knl == null)
                Assert.Fail("Instance is not correct.");
            if(knl.Count != 2)
                Assert.Fail("Instance is not correct.");

            if(!knl.Contains(k1.KeyName))
                Assert.Fail("Instance is not correct.");
            if(!knl.Contains(k2.KeyName))
                Assert.Fail("Instance is not correct.");
        }
        // Test 61  Populate a keystore with different types of keys.
        //          Get the key names of just symmetric keys.
        [TestMethod]
        public void Test61()
        {
            // Create a test key...
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k1);
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);
            KeyStore_v2_Base.Create_New_ECDSA_KeyPair(Guid.NewGuid().ToString(), out var k3);
            KeyStore_v2_Base.Create_New_RSA_KeyPair(Guid.NewGuid().ToString(), 512, out var k4);

            // Add keys to the store...
            var ks = new KeyStore_v2_Base();
            ks.AddKey_toStore(k1);
            ks.AddKey_toStore(k2);
            ks.AddKey_toStore(k3);
            ks.AddKey_toStore(k4);

            if (ks.KeyCount != 4)
                Assert.Fail("Instance is not correct.");

            // Get the keynames of just symmetric keys...
            // Look through the keystore for the first available key that is:
            // Symmetric, AES, enabled, has private key, 
            var filter = OGA.DomainBase.QueryHelpers.PredicateBuilder.True<KeyObject_v2>();
            filter = filter.And<KeyObject_v2>(t => t.Is_SymmetricKey());

            var knl = ks.GetKeyNames_fromStore(filter);

            if(knl == null)
                Assert.Fail("Instance is not correct.");
            if(knl.Count != 2)
                Assert.Fail("Instance is not correct.");

            if(!knl.Contains(k1.KeyName))
                Assert.Fail("Instance is not correct.");
            if(!knl.Contains(k2.KeyName))
                Assert.Fail("Instance is not correct.");
            if(knl.Contains(k3.KeyName))
                Assert.Fail("Instance is not correct.");
            if(knl.Contains(k4.KeyName))
                Assert.Fail("Instance is not correct.");
        }

        // Test 62  Populate a keystore with keys.
        //          Get the key metadata of each.
        [TestMethod]
        public void Test62()
        {
            // Create a test key...
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k1);
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);

            // Add both keys to the store...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);
            var res2 = ks.AddKey_toStore(k2);

            if(res1 != 1)
                Assert.Fail("Instance is not correct.");
            if(res2 != 1)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(k1.KeyName) == false)
                Assert.Fail("Instance is not correct.");
            if(ks.HasKey_inStore(k2.KeyName) == false)
                Assert.Fail("Instance is not correct.");
            if (ks.KeyCount != 2)
                Assert.Fail("Instance is not correct.");

            // Get the keynames list...
            var knl = ks.GetKeyMetadata_fromStore(null);

            if(knl == null)
                Assert.Fail("Instance is not correct.");
            if(knl.Count != 2)
                Assert.Fail("Instance is not correct.");

            if(!knl.Any(m=>m.KeyName == k1.KeyName))
                Assert.Fail("Instance is not correct.");
            if(!knl.Any(m=>m.KeyName == k2.KeyName))
                Assert.Fail("Instance is not correct.");
        }
        // Test 63  Populate a keystore with different types of keys.
        //          Get the key metadata of just symmetric keys.
        [TestMethod]
        public void Test63()
        {
            // Create a test key...
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k1);
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);
            KeyStore_v2_Base.Create_New_ECDSA_KeyPair(Guid.NewGuid().ToString(), out var k3);
            KeyStore_v2_Base.Create_New_RSA_KeyPair(Guid.NewGuid().ToString(), 512, out var k4);

            // Add keys to the store...
            var ks = new KeyStore_v2_Base();
            ks.AddKey_toStore(k1);
            ks.AddKey_toStore(k2);
            ks.AddKey_toStore(k3);
            ks.AddKey_toStore(k4);

            if (ks.KeyCount != 4)
                Assert.Fail("Instance is not correct.");

            // Get the keynames of just symmetric keys...
            // Look through the keystore for the first available key that is:
            // Symmetric, AES, enabled, has private key, 
            var filter = OGA.DomainBase.QueryHelpers.PredicateBuilder.True<KeyObject_v2>();
            filter = filter.And<KeyObject_v2>(t => t.Is_SymmetricKey());

            var knl = ks.GetKeyMetadata_fromStore(filter);

            if(knl == null)
                Assert.Fail("Instance is not correct.");
            if(knl.Count != 2)
                Assert.Fail("Instance is not correct.");

            if(!knl.Any(m=>m.KeyName == k1.KeyName))
                Assert.Fail("Instance is not correct.");
            if(!knl.Any(m=>m.KeyName == k2.KeyName))
                Assert.Fail("Instance is not correct.");
            if(knl.Any(m=>m.KeyName == k3.KeyName))
                Assert.Fail("Instance is not correct.");
            if(knl.Any(m=>m.KeyName == k4.KeyName))
                Assert.Fail("Instance is not correct.");
        }

        // Test 64  Populate a keystore with keys.
        //          Get the key object of each.
        [TestMethod]
        public void Test64()
        {
            // Create a test key...
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k1);
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);

            // Add both keys to the store...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);
            var res2 = ks.AddKey_toStore(k2);

            if(res1 != 1)
                Assert.Fail("Instance is not correct.");
            if(res2 != 1)
                Assert.Fail("Instance is not correct.");

            if(ks.HasKey_inStore(k1.KeyName) == false)
                Assert.Fail("Instance is not correct.");
            if(ks.HasKey_inStore(k2.KeyName) == false)
                Assert.Fail("Instance is not correct.");
            if (ks.KeyCount != 2)
                Assert.Fail("Instance is not correct.");

            // Get the keys list...
            var knl = ks.GetKeys_fromStore(null);

            if(knl == null)
                Assert.Fail("Instance is not correct.");
            if(knl.Count != 2)
                Assert.Fail("Instance is not correct.");

            if(!knl.Any(m=>m.KeyName == k1.KeyName))
                Assert.Fail("Instance is not correct.");
            if(!knl.Any(m=>m.KeyName == k2.KeyName))
                Assert.Fail("Instance is not correct.");
        }
        // Test 65  Populate a keystore with different types of keys.
        //          Get the key object of just symmetric keys.
        [TestMethod]
        public void Test65()
        {
            // Create a test key...
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k1);
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);
            KeyStore_v2_Base.Create_New_ECDSA_KeyPair(Guid.NewGuid().ToString(), out var k3);
            KeyStore_v2_Base.Create_New_RSA_KeyPair(Guid.NewGuid().ToString(), 512, out var k4);

            // Add keys to the store...
            var ks = new KeyStore_v2_Base();
            ks.AddKey_toStore(k1);
            ks.AddKey_toStore(k2);
            ks.AddKey_toStore(k3);
            ks.AddKey_toStore(k4);

            if (ks.KeyCount != 4)
                Assert.Fail("Instance is not correct.");

            // Get the keynames of just symmetric keys...
            // Look through the keystore for the first available key that is:
            // Symmetric, AES, enabled, has private key, 
            var filter = OGA.DomainBase.QueryHelpers.PredicateBuilder.True<KeyObject_v2>();
            filter = filter.And<KeyObject_v2>(t => t.Is_SymmetricKey());

            var knl = ks.GetKeys_fromStore(filter);

            if(knl == null)
                Assert.Fail("Instance is not correct.");
            if(knl.Count != 2)
                Assert.Fail("Instance is not correct.");

            if(!knl.Any(m=>m.KeyName == k1.KeyName))
                Assert.Fail("Instance is not correct.");
            if(!knl.Any(m=>m.KeyName == k2.KeyName))
                Assert.Fail("Instance is not correct.");
            if(knl.Any(m=>m.KeyName == k3.KeyName))
                Assert.Fail("Instance is not correct.");
            if(knl.Any(m=>m.KeyName == k4.KeyName))
                Assert.Fail("Instance is not correct.");
        }
    }
}