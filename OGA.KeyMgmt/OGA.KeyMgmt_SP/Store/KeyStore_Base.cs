using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using OGA.SharedKernel.Extensions.DateandTime;
using OGA.KeyMgmt.Model;

namespace OGA.KeyMgmt.Store
{
    public class KeyStore_Base
    {
        static public int Latest_KeyStoreVersion = 2;

        static public string CONST_Default_StorageKeyName = "storage";
        static public string CONST_Default_PrivKey_EncryptionKeyName = "privkey_key";
    }
    /// <summary>
    /// Memory-backed keystore, used to hold keys that are passed in from other sources, or for testing.
    /// </summary>
    public class KeyStore_v2_Base : KeyStore_Base
    {
        #region Private Fields

        protected Dictionary<string, KeyObject_v2> _keys;

        protected int _keystoreversion = 2;

        protected volatile int dataversion = 0;

        #endregion


        #region Public Properties

        /// <summary>
        /// Labels the keystore as: memory, json string, file, database, etc...
        /// </summary>
        virtual public string KeyStoreType { get => "Base"; }

        /// <summary>
        /// Key Store Version.
        /// </summary>
        public int KeyStoreVersion { get => _keystoreversion; }

        public DateTime CreationDateUTC { get; set; }
        public DateTime LastUpdateUTC { get; set; }

        /// <summary>
        /// Incrementing version of the stored data.
        /// Increments each time a key is added, changed, or removed.
        /// </summary>
        public int DataVersion { get => dataversion; }

        public int KeyCount { get => this._keys.Count; }

        #endregion


        #region ctor / dtor

        /// <summary>
        /// Creates a keystore instance. This class type is memory-based, with no persistent backing store.
        /// </summary>
        public KeyStore_v2_Base()
        {
            this.CreationDateUTC = DateTime.UtcNow.TruncateToSecond();
            this.LastUpdateUTC = this.CreationDateUTC;

            this._keys = new Dictionary<string, KeyObject_v2>();
        }

        #endregion


        #region Public Methods

        public int AddKey_toStore(KeyObject_v2 key)
        {
            // Check if the key name is already in the store...
            if(this._keys.ContainsKey(key.KeyName))
            {
                // The key name exists.
                // We cannot add it.

                return 0;
            }
            // If here, the key is not in the store.
            // We can add it.

            // Make a deep copy of the key, so the instance we keep is our own, and not accessible externally...
            KeyObject_v2 k2 = new KeyObject_v2();
            key.CopyTo_withKeyData(k2);

            this._keys.Add(k2.KeyName, k2);

            dataversion++;
            this.LastUpdateUTC = DateTime.UtcNow.TruncateToSecond();

            return 1;
        }

        public bool HasKey_inStore(string keyname)
        {
            if (this._keys.ContainsKey(keyname))
                return true;
            else
                return false;
        }

        public int GetKey_fromStore(string keyname, out KeyObject_v2 key)
        {
            if(!this._keys.TryGetValue(keyname, out var k1))
            {
                key = null;
                return 0;
            }

            // Make a deep copy of the key, so the instance we keep is our own, and not accessible externally...
            KeyObject_v2 k2 = new KeyObject_v2();
            k1.CopyTo_withKeyData(k2);

            key = k2;
            return 1;
        }

        /// <summary>
        /// Retrieves a list of key names for keys that match a given query filter.
        /// This method accepts a query filter that can search based on any property of a key object.
        /// For examples of how to compose a filter predicate, see: https://github.com/LeeWhite187/OGA.DomainBase/blob/main/OGA.DomainBase/OGA.DomainBase_SP/QueryHelpers/PredicateBuilder.cs
        /// </summary>
        /// <param name="filter"></param>
        /// <returns></returns>
        public List<string> GetKeyNames_fromStore(System.Linq.Expressions.Expression<Func<KeyObject_v2, bool>> filter)
        {
            try
            {
                List<string> l = null;

                if(filter == null)
                {
                    // The caller wants all keys.
                    l = this._keys.Values.Select(m=>m.KeyName).ToList();
                }
                else
                {
                    // The caller gave us a filter.

                    // Since our query is over an in-memory collection, we must compile the expression, first...
                    // NOTE: For Linq-to-SQL queries, such as using EF, we would use the naked (uncompiled) filter against the dataset's IQueryable,
                    // NOTE: which allows Linq to compile the expression to a SQL filter clause.
                    // For usage, here, we compile the filter predicate (since there is no hand-off to query-optimization logic).
                    var compiledfilter = filter.Compile();

                    // Now, we can search the key values collection for the desired entries...
                    l = this._keys.Values.Where(compiledfilter).Select(m=>m.KeyName).ToList();
                }

                return l;
            }
            catch(Exception)
            {
                return new List<string>();
            }
        }

        /// <summary>
        /// Retrieves a list of key metadata for keys that match a given query filter.
        /// This method accepts a query filter that can search based on any property of a key object.
        /// For examples of how to compose a filter predicate, see: https://github.com/LeeWhite187/OGA.DomainBase/blob/main/OGA.DomainBase/OGA.DomainBase_SP/QueryHelpers/PredicateBuilder.cs
        /// </summary>
        /// <param name="filter"></param>
        /// <returns></returns>
        public List<KeyObject_v2> GetKeyMetadata_fromStore(System.Linq.Expressions.Expression<Func<KeyObject_v2, bool>> filter)
        {
            try
            {
                List<KeyObject_v2> l = null;

                if(filter == null)
                {
                    // The caller wants all keys.
                    l = this._keys.Values.ToList();
                }
                else
                {
                    // The caller gave us a filter.

                    // Since our query is over an in-memory collection, we must compile the expression, first...
                    // NOTE: For Linq-to-SQL queries, such as using EF, we would use the naked (uncompiled) filter against the dataset's IQueryable,
                    // NOTE: which allows Linq to compile the expression to a SQL filter clause.
                    // For usage, here, we compile the filter predicate (since there is no hand-off to query-optimization logic).
                    var compiledfilter = filter.Compile();

                    // Now, we can search the key values collection for the desired entries...
                    l = this._keys.Values.Where(compiledfilter).ToList();
                }

                // Make a copy of just the key metadata...
                var kl = new List<KeyObject_v2>();
                foreach(var k in l)
                {
                    KeyObject_v2 k2 = new KeyObject_v2();
                    k.CopyTo_withoutKeyData(k2);

                    kl.Add(k2);
                }

                return kl;
            }
            catch(Exception)
            {
                return new List<KeyObject_v2>();
            }
        }

        /// <summary>
        /// Retrieves a list of key that match a given query filter.
        /// This method accepts a query filter that can search based on any property of a key object.
        /// For examples of how to compose a filter predicate, see: https://github.com/LeeWhite187/OGA.DomainBase/blob/main/OGA.DomainBase/OGA.DomainBase_SP/QueryHelpers/PredicateBuilder.cs
        /// </summary>
        /// <param name="filter"></param>
        /// <returns></returns>
        public List<KeyObject_v2> GetKeys_fromStore(System.Linq.Expressions.Expression<Func<KeyObject_v2, bool>> filter)
        {
            try
            {
                List<KeyObject_v2> l = null;

                if(filter == null)
                {
                    // The caller wants all keys.
                    l = this._keys.Values.ToList();
                }
                else
                {
                    // The caller gave us a filter.

                    // Since our query is over an in-memory collection, we must compile the expression, first...
                    // NOTE: For Linq-to-SQL queries, such as using EF, we would use the naked (uncompiled) filter against the dataset's IQueryable,
                    // NOTE: which allows Linq to compile the expression to a SQL filter clause.
                    // For usage, here, we compile the filter predicate (since there is no hand-off to query-optimization logic).
                    var compiledfilter = filter.Compile();

                    // Now, we can search the key values collection for the desired entries...
                    l = this._keys.Values.Where(compiledfilter).ToList();
                }

                // Make a deep copy of the key, so the instance we keep is our own, and not accessible externally...
                var kl = new List<KeyObject_v2>();
                foreach(var k in l)
                {
                    KeyObject_v2 k2 = new KeyObject_v2();
                    k.CopyTo_withKeyData(k2);

                    kl.Add(k2);
                }

                return kl;
            }
            catch(Exception)
            {
                return new List<KeyObject_v2>();
            }
        }

        /// <summary>
        /// Provides a means to find the oldest key that matches the given query filter.
        /// This method accepts a query filter that can search based on any property of a key object.
        /// For examples of how to compose a filter predicate, see: https://github.com/LeeWhite187/OGA.DomainBase/blob/main/OGA.DomainBase/OGA.DomainBase_SP/QueryHelpers/PredicateBuilder.cs
        /// </summary>
        /// <param name="filterpredicate"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public int GetOldestKey_fromStore_byFilter(System.Linq.Expressions.Expression<Func<KeyObject_v2, bool>> filterpredicate, out KeyObject_v2 key)
        {
            try
            {
                // Since our query is over an in-memory collection, we must compile the expression, first...
                // NOTE: For Linq-to-SQL queries, such as using EF, we would use the naked (uncompiled) filter against the dataset's IQueryable,
                // NOTE: which allows Linq to compile the expression to a SQL filter clause.
                // For usage, here, we compile the filter predicate (since there is no hand-off to query-optimization logic).
                var compiledfilter = filterpredicate.Compile();

                // Now, we can search the key values collection for the desired entries...
                var k1 = this._keys.Values.Where(compiledfilter).OrderBy(n => n.CreationUTC).First();

                // Make a deep copy of the key, so the instance we keep is our own, and not accessible externally...
                KeyObject_v2 k2 = new KeyObject_v2();
                k1.CopyTo_withKeyData(k2);

                key = k2;
                return 1;
            }
            catch(Exception)
            {
                key = null;
                return 0;
            }
        }
        /// <summary>
        /// Provides a means to find the most recently created key that matches the given query filter.
        /// This method accepts a query filter that can search based on any property of a key object.
        /// For examples of how to compose a filter predicate, see: https://github.com/LeeWhite187/OGA.DomainBase/blob/main/OGA.DomainBase/OGA.DomainBase_SP/QueryHelpers/PredicateBuilder.cs
        /// </summary>
        /// <param name="filterpredicate"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public int GetNewestKey_fromStore_byFilter(System.Linq.Expressions.Expression<Func<KeyObject_v2, bool>> filterpredicate, out KeyObject_v2 key)
        {
            try
            {
                // Since our query is over an in-memory collection, we must compile the expression, first...
                // NOTE: For Linq-to-SQL queries, such as using EF, we would use the naked (uncompiled) filter against the dataset's IQueryable,
                // NOTE: which allows Linq to compile the expression to a SQL filter clause.
                // For usage, here, we compile the filter predicate (since there is no hand-off to query-optimization logic).
                var compiledfilter = filterpredicate.Compile();

                // Now, we can search the key values collection for the desired entries...
                var k1 = this._keys.Values.Where(compiledfilter).OrderByDescending(n => n.CreationUTC).First();

                // Make a deep copy of the key, so the instance we keep is our own, and not accessible externally...
                KeyObject_v2 k2 = new KeyObject_v2();
                k1.CopyTo_withKeyData(k2);

                key = k2;
                return 1;
            }
            catch(Exception)
            {
                key = null;
                return 0;
            }
        }

        public int UpdateKey_inStore(KeyObject_v2 key)
        {
            // Check if the key exists...
            if(!this._keys.ContainsKey(key.KeyName))
            {
                // The key is not in the store.
                // Nothing to update.
                return 0;
            }

            // Check if the key will be changed...
            if(this._keys[key.KeyName].CompareTo(key))
            {
                // The given key is different than the one we have.

                // Make a deep copy of the key, so the instance we keep is our own, and not accessible externally...
                KeyObject_v2 k2 = new KeyObject_v2();
                key.CopyTo_withKeyData(k2);

                // Update the key in the store...
                this._keys[key.KeyName] = k2;

                dataversion++;
                this.LastUpdateUTC = DateTime.UtcNow.TruncateToSecond();
            }

            return 1;
        }

        public void RemoveKey_fromStore(KeyObject_v2 key)
        {
            RemoveKey_fromStore(key.KeyName);
        }
        public void RemoveKey_fromStore(string keyname)
        {
            // Check if the key name is already in the store...
            if(!this._keys.ContainsKey(keyname))
            {
                // The key name does not exists.

                return;
            }
            // If here, the key is in the store.
            // We can remove it.

            dataversion++;
            this.LastUpdateUTC = DateTime.UtcNow.TruncateToSecond();

            this._keys.Remove(keyname);
        }

        static public int Create_New_RSA_KeyPair(string keyname, int keysize, out KeyObject_v2 key)
        {
            // Ensure the given key size is at least 512 bits.
            // Otherwise, the exportcspBlob call will throw an Invalid Flags Specified exception.
            if(keysize < 512)
            {
                // The caller is requesting a key size that is too short.

                key = null;
                return -1;
            }

            // Create a crypto provider to use...
            System.Security.Cryptography.RSACryptoServiceProvider csp = new System.Security.Cryptography.RSACryptoServiceProvider(keysize);
            // The above call generated a random key for us.

            // Get the private and public key pairs of the above key...
            byte[] privkey = csp.ExportCspBlob(true);
            byte[] pubkey = csp.ExportCspBlob(false);

            // Convert the key pair to base64.
            string b64privkey = Convert.ToBase64String(privkey);
            string b64pubkey = Convert.ToBase64String(pubkey);

            // Create a key instance and populate it...
            KeyObject_v2 k = new KeyObject_v2();
            k.KeyLength = keysize;
            k.KeyName = keyname;
            k.KeyType = eKeyType.RSA.ToString();

            k.PrivateKey = b64privkey;
            k.PrivEncrypted = false;

            k.IsBase64Encoded = true;
            k.HasPrivateKey = true;

            k.PublicKey = b64pubkey;
            k.HasPublicKey = true;

            k.Status = eKeyStatus.Enabled;
            k.CreationUTC = DateTime.UtcNow;
            k.LastUpdateUTC = k.CreationUTC;

            // Pass the key back to the caller...
            key = k;
            return 1;
        }

        /// <summary>
        /// Generates a new ECDSA key with the NISTP256 curve.
        /// NOTE: ECDSA keys are for signing and verifying data.
        /// </summary>
        /// <param name="keyname"></param>
        /// <param name="key"></param>
        /// <param name="privatekey_encryptionkey"></param>
        /// <returns></returns>
        static public int Create_New_ECDSA_KeyPair(string keyname, out KeyObject_v2 key)
        {
            // Create a new key...
            ECDsa eckey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            // Get the private and public key pairs of the above key...
            var privkey = eckey.ExportECPrivateKey();
            var pubkey = eckey.ExportSubjectPublicKeyInfo();

            // Convert the key pair to base64.
            string b64privkey = Convert.ToBase64String(privkey);
            string b64pubkey = Convert.ToBase64String(pubkey);

            // Create a key instance and populate it...
            KeyObject_v2 k = new KeyObject_v2();
            k.KeyLength = 256;
            k.KeyName = keyname;
            k.KeyType = eKeyType.ECDSA.ToString();

            k.PrivateKey = b64privkey;
            k.PrivEncrypted = false;

            k.IsBase64Encoded = true;
            k.HasPrivateKey = true;

            k.PublicKey = b64pubkey;
            k.HasPublicKey = true;

            k.Status = eKeyStatus.Enabled;
            k.CreationUTC = DateTime.UtcNow;
            k.LastUpdateUTC = k.CreationUTC;

            // Pass the key back to the caller...
            key = k;
            return 1;
        }

        static public int Create_New_AES_Key(string keyname, int keysize, out KeyObject_v2 key)
        {
            // Create the symmetric key data for an AES key...
            byte[] aeskeydata = new byte[] { };
            if (Generate_AES256_KeyBytes(out aeskeydata) != 1)
            {
                // Failed to create new AES key data.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error("Failed to create new AES key data.");

                key = null;
                return -1;
            }

            // Convert the key pair to base64.
            string b64privkey = Convert.ToBase64String(aeskeydata);

            // Create a key instance and populate it...
            KeyObject_v2 k = new KeyObject_v2();
            k.KeyLength = keysize;
            k.KeyName = keyname;
            k.KeyType = eKeyType.AES.ToString();

            k.PrivateKey = b64privkey;
            k.PrivEncrypted = false;

            k.IsBase64Encoded = true;
            k.HasPrivateKey = true;

            k.PublicKey = "";
            k.HasPublicKey = false;

            k.Status = eKeyStatus.Enabled;
            k.CreationUTC = DateTime.UtcNow;
            k.LastUpdateUTC = k.CreationUTC;

            // Pass the key back to the caller...
            key = k;
            return 1;
        }

        static public int Verify_RSAKeyPair(KeyObject_v2 kobj)
        {
            string b64privkey = "";
            string candidate_string = "";
            byte[] hashbytes = new byte[] { };

            // Check that the given key is an RSA keypair...
            if (kobj.KeyType != eKeyType.RSA.ToString())
            {
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        $"Keypair is not a valid RSA keytype.");

                return -1;
            }

            // See if the private key is encrypted or not.
            if (kobj.PrivEncrypted)
            {
                // The private key is encrypted.
                // We don't have a key to decrypt it with.
                // So, we must return an error.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        $"Private key is encrypted, but no storage password was given.");

                return -1;
            }
            else
            {
                // The private key is not encrypted.
                // We will load it without transform.
                b64privkey = kobj.PrivateKey;
            }
            // If here, we have the private key, ready for loading.

            try
            {
                // Compose a string that we will test with...
                candidate_string = "The quick brown fox jumped over the lazy dog";

                // Convert the candidate string to a byte array...
                byte[] candidatebytes = OGA.KeyMgmt.Helper.Conversions.String_to_Byte(candidate_string);

                // Create a hash of the byte array...
                System.Security.Cryptography.SHA1 sec = new System.Security.Cryptography.SHA1CryptoServiceProvider();
                hashbytes = sec.ComputeHash(candidatebytes);
            }
            catch (Exception e)
            {
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                        "Exception occurred while hasing the test string.");

                return -3;
            }

            try
            {
                // Convert the private key to a byte array...
                byte[] privkey = Convert.FromBase64String(b64privkey);
                byte[] pubkey = Convert.FromBase64String(kobj.PublicKey);

                // Create a pair of crypto providers to use...
                // We make one with the private/public key pair for signing.
                // And, we make one with only the public key for verifying, same as is done in a client.
                System.Security.Cryptography.RSACryptoServiceProvider csp_signer = new System.Security.Cryptography.RSACryptoServiceProvider(kobj.KeyLength);
                System.Security.Cryptography.RSACryptoServiceProvider csp_verifier = new System.Security.Cryptography.RSACryptoServiceProvider(kobj.KeyLength);
                // Load the private and public key data into the providers...
                csp_signer.ImportCspBlob(privkey);
                csp_verifier.ImportCspBlob(pubkey);

                // Sign the hash data with our private key...
                byte[] signature = csp_signer.SignHash(hashbytes, System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA1"));

                // Verify the signature is good...
                bool result = csp_verifier.VerifyHash(hashbytes, System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA1"), signature);

                if (!result)
                {
                    // Failed to verify the signature of the hash.
                    // This is fatal to any signing activity that uses the given key.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                            $"Verification failed for key {kobj.KeyName}.");

                    return -4;
                }
                // If here, we have verified that the private and public key pair are good to use.

                return 1;
            }
            catch (Exception e)
            {
                // Exception caught while attempting to check that we can sign and verify with the key pair.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                        $"Exception caught while attempting to check that we can sign and verify with key {kobj.KeyName}.");

                return -10;
            }
        }

        static public int Verify_ECDSAKeyPair(KeyObject_v2 kobj)
        {
            string b64privkey = "";
            byte[] candidatebytes = new byte[] { };
            byte[] signaturebytes = new byte[] { };

            // Check that the given key is an ECDSA keypair...
            if (kobj.KeyType != eKeyType.ECDSA.ToString())
            {
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        $"Keypair is not a valid ECDSA keytype.");

                return -1;
            }

            // See if the private key is encrypted or not.
            if (kobj.PrivEncrypted)
            {
                // The private key is encrypted.
                // We don't have a key to decrypt it with.
                // So, we must return an error.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        $"Private key is encrypted, but no storage password was given.");

                return -1;
            }
            else
            {
                // The private key is not encrypted.
                // We will load it without transform.
                b64privkey = kobj.PrivateKey;
            }
            // If here, we have the private key, ready for loading.

            // Compose a string that we will test with...
            var candidate_string = "The quick brown fox jumped over the lazy dog";
            // Convert the candidate string to a byte array...
            candidatebytes = OGA.KeyMgmt.Helper.Conversions.String_to_Byte(candidate_string);

            try
            {
                // Convert the private key to a byte array...
                byte[] privkey = Convert.FromBase64String(b64privkey);
                byte[] pubkey = Convert.FromBase64String(kobj.PublicKey);

                // Create the EC crypto provider, and load it with the private and public key data...
                ECDsa eckey_sign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                eckey_sign.ImportECPrivateKey(privkey, out _);

                // Attempt to hash and sign the candidate string...
                signaturebytes = eckey_sign.SignData(candidatebytes, HashAlgorithmName.SHA256);

                // And, create a second key instance for verification...
                ECDsa eckey_ver = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                eckey_ver.ImportSubjectPublicKeyInfo(pubkey, out _);


                // Now, we need to verify the signature is good, which tests the public key...
                bool result = eckey_ver.VerifyData(candidatebytes, signaturebytes, HashAlgorithmName.SHA256);

                if (!result)
                {
                    // Failed to verify the signature of the hash.
                    // This is fatal to any signing activity that uses the given key.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                            $"Verification failed for key {kobj.KeyName}.");

                    return -4;
                }
                // If here, we have verified that the private and public key pair are good to use.

                return 1;
            }
            catch (Exception e)
            {
                // Exception caught while attempting to check that we can sign and verify with the key pair.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                        $"Exception caught while attempting to check that we can sign and verify with key {kobj.KeyName}.");

                return -10;
            }
        }

        static public int Verify_AESKey(KeyObject_v2 kobj)
        {
            string privkey = "";
            string candidate_string = "";
            string cyphertext = null;
            string decrypted_string = "";

            // Check that the given key is an AES key...
            if (kobj.KeyType != eKeyType.AES.ToString())
            {
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        $"Keypair is not a valid AES key.");

                return -1;
            }

            // See if the private key is encrypted or not.
            if (kobj.PrivEncrypted)
            {
                // The private key is encrypted.
                // We don't have a key to decrypt it with.
                // So, we must return an error.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        $"Private key is encrypted, but no storage password was given.");

                return -1;
            }
            else
            {
                // The private key is not directly encrypted.
                // We will load it without transform.
                privkey = kobj.PrivateKey;
            }
            // If here, we have the private key, ready for loading.

            // Compose a string that we will test with...
            candidate_string = "The quick brown fox jumped over the lazy dog";

            // Encrypt the test data...
            try
            {
                // To use the .NET AES implementation, we need a string key.
                // This can be either base64 encoded or a plain text password.
                // Either way, we already have a private key in a native string datatype.
                // So, we will simply use it without manipulation.

                // Encrypt the test data...
                cyphertext = OGA.KeyMgmt.Helper.AES256Crypto.EncryptStringAES(candidate_string, privkey);
            }
            catch (Exception e)
            {
                // Exception caught while attempting to check that we can sign and verify with the key pair.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                        $"Exception caught while attempting to check that we can sign and verify with key {kobj.KeyName}.");

                return -10;
            }

            // Decrypt the test data...
            try
            {
                // Same as before...
                // To use the .NET AES implementation, we need a string key.
                // This can be either base64 encoded or a plain text password.
                // Either way, we already have a private key in a native string datatype.
                // So, we will simply use it without manipulation.

                // Decrypt the test data...
                decrypted_string = OGA.KeyMgmt.Helper.AES256Crypto.DecryptStringAES(cyphertext, privkey);

                // Check if the source string was recovered...
                if (decrypted_string != candidate_string)
                {
                    // Key failed to encrypt and decrypt the same value.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                            $"Verification failed for key {kobj.KeyName}.");

                    return -4;
                }
                // If here, we have verified that the AES key is good to use.

                return 1;
            }
            catch (Exception e)
            {
                // Exception caught while attempting to check that the AES key is good.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                        $"Exception caught while attempting to check that the AES key is good: KeyName = {kobj.KeyName}.");

                return -10;
            }
        }

        #endregion


        #region Private Methods

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

        static private int Generate_AES256_KeyBytes(out byte[] keybytes)
        {
            int key_bitsize = 256;

            // Create data for the AES symmetric key...
            byte[] kb = Create_AES_KeyData(key_bitsize);

            // Pass back the created key...
            keybytes = kb;
            return 1;
        }

        static private byte[] Create_AES_KeyData(int keysize)
        {
            byte[] keyBytes = new byte[keysize / 8];

            // Create a random set of bytes...
            var fff = new Nanoid.CryptoRandom();
            fff.NextBytes(keyBytes);

            return keyBytes;
        }

        /// <summary>
        /// Used by a constructor that receives a simple storage password as a string.
        /// Returns a key object instance for localized key usage.
        /// </summary>
        /// <param name="storageencryptionkey"></param>
        /// <returns></returns>
        protected KeyObject_v2 Create_Simple_AES256KeyObject(string name, string storageencryptionkey)
        {
            var k = new KeyObject_v2();
            k.KeyName = name;
            k.CreationUTC = DateTime.UtcNow;
            k.LastUpdateUTC = k.CreationUTC;

            k.KeyType = eKeyType.AES.ToString();
            k.KeyLength = 256;
            k.PrivateKey = storageencryptionkey;

            k.Status = eKeyStatus.Enabled;
            k.PrivEncrypted = false;
            k.HasPublicKey = false;
            k.HasPrivateKey = true;
            k.PublicKey = "";

            return k;
        }

        #endregion
    }
}
