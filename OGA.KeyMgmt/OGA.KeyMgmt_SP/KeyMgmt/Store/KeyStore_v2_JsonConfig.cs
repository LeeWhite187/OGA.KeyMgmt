using System;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using OGA.SharedKernel.Exceptions;
using OGA.KeyMgmt.Config;
using OGA.KeyMgmt.Model;

namespace OGA.KeyMgmt.Store
{
    public class KeyStore_v2_JsonConfig : KeyStore_v2_Base
    {
        #region Private Fields

        protected KeyObject_v2 _storageencryptionkey;

        #endregion


        #region Public Properties

        /// <summary>
        /// Labels the keystore as: memory, json string, file, database, etc...
        /// </summary>
        override public string KeyStoreType { get => "Json"; }

        #endregion


        #region ctor / dtor

        /// <summary>
        /// Creates a keystore instance that is json config based.
        /// </summary>
        public KeyStore_v2_JsonConfig() : base()
        {
            // No storage password was given.
            // Leave it null.
            _storageencryptionkey = null;
        }

        /// <summary>
        /// Creates a keystore instance that is json config based.
        /// Accepts the storage password.
        /// </summary>
        /// <param name="storageencryptionkey"></param>
        public KeyStore_v2_JsonConfig(string storageencryptionkey) : base()
        {
            // Set the storage key if the password was defined...
            if (!string.IsNullOrEmpty(storageencryptionkey))
            {
                // The caller passed in a storage password as a string.
                // We will assume this is an AES256 key, and create a key object to localize it...
                _storageencryptionkey = Create_Simple_AES256KeyObject(CONST_Default_StorageKeyName, storageencryptionkey);
            }
            else
                _storageencryptionkey = null;
        }

        /// <summary>
        /// Creates a keystore instance that is json config based.
        /// Accepts the storage password as an AES256 symmetric key.
        /// </summary>
        /// <param name="storageencryptionkey"></param>
        public KeyStore_v2_JsonConfig(KeyObject_v2 storageencryptionkey) : base()
        {
            _storageencryptionkey = storageencryptionkey;
        }

        #endregion


        #region Storage Methods

        public int Load(KeyStore_StorageStruct config)
        {
            // The config contains several fields saved in json form:
            //  Algo - defines the algorithm used to encrypt the header and data sections.
            //  KeyId - defines the key used for encrypting the header and data sections.
            //  Header - contains the encrypted version of the keystore.
            //  Data - contains the encrypted list of keys stored.

            // Some rules exists about the keystore file:
            //  If the header contains a newer store version, we cannot open the store.
            //  If the header contains an older store version, we can migrate the store and open it.

            OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                "Checking if key store config exists...");

            // Check that the config is valid.
            if (config == null)
            {
                // Given config is null.
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Key store json config is null.");

                return -1;
            }
            if (string.IsNullOrEmpty(config.KeyData))
            {
                // Given config is invalid.
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Key store json config is null.");

                return -2;
            }

            // Check that we have an algorithm for storage...
            if(!Have_Algo_for_Keystore(config.Storage_Algo))
            {
                // No algorithm is defined for the keystore.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Key store json config was encrypted with an unknown algorithm.");

                return -3;
            }

            // Check if we have an algo for signing...
            if(!Have_SigningAlgo_for_Keystore(config.Signing_Algo))
            {
                // No algorithm is defined for the keystore.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Key store json config was signed with an unknown algorithm.");

                return -4;
            }

            // Check that we have the necessary key to decrypt the keystore...
            if(!Have_StorageKey_for_Keystore(config.Storage_KeyId))
            {
                // The keystore was saved with a different key than we were given.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Key store json config was storage encrypted with different key.");

                return -4;
            }

            OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                "Key store config can be parsed.");

            // Get the KeystoreVersion...
            int ver = config.KeystoreVersion;
            if (ver <= 0)
            {
                // Failed to recover the KeystoreVersion from the candidate key store config.
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Failed to recover the KeystoreVersion from the candidate key store config.");

                return -5;
            }

            OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                "KeystoreVersion recovered from key store config. KeystoreVersion is {0}", ver.ToString());

            // Check that the KeystoreVersion matches our version.
            if (ver == this.KeyStoreVersion)
            {
                // The offline KeystoreVersion is the same as our KeystoreVersion.

                // The KeystoreVersion matches.
                // We can read it in without any migration.

                // Get the encryption algorithm and keyid...
                var signingalgo = config.Storage_Algo;
                var storagealgo = config.Storage_Algo;
                var keyid = config.Storage_KeyId;

                // Check if the struct was signed...
                // This would be indicated by 

                // Verify the signature of the store struct...
                if(!Verify_KeystoreStruct_Signature(config))
                {
                    // The keystore struct signature failed verification.
                    // We must assume it is corrupt, malformed, or has been tampered with.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        "Keystore signature did not pass verification. The keystore struct is malformed or tampered.");

                    return -6;
                }
                // If here, the keystore struct passed validation.
                // We can trust its contents.

                // Decrypt the data section using the given algo and keyid...
                string data = DecryptData(storagealgo, keyid, config.KeyData);
                // Check that we recovered the data section...
                if(string.IsNullOrEmpty(data))
                {
                    // Failed to decrypt the keystore data section.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        "Failed to decrypt the keystore data section.");

                    return -6;
                }

                // With the data section decrypted, we need to attempt to convert it to a list of keys.
                try
                {
                    // Convert the data to our key listing.
                    List<KeyObject_v2> kkk = Newtonsoft.Json.JsonConvert.DeserializeObject<List<KeyObject_v2>>(data);

                    // Copy the keys into our dictionary...
                    // If the keyname is a duplicate, this will throw an exception.
                    foreach(var k in kkk)
                    {
                        this._keys.Add(k.KeyName, k);
                    }

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                        "Key store config read successfully.");

                    // Load metadata from the struct...
                    this.dataversion = config.DataVersion;
                    this.CreationDateUTC = config.CreationDateUTC;
                    this.LastUpdateUTC = config.LastUpdateUTC;

                    // Return success.
                    return 1;
                }
                catch (Exception e)
                {
                    // Exception occurred while attempting to convert the data section to our key list.
                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                        "Exception occurred while attempting to convert the data section to our key list.");

                    return -7;
                }
            }
            else if(ver < Latest_KeyStoreVersion)
            {
                // The KeystoreVersion of the keystore config does not match this KeystoreVersion of class.
                // It is older than current and must be migrated to our KeystoreVersion to be used.
                // We will migrate its content as we open it.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "The KeystoreVersion of the keystore config is older than current and will be migrated during load.");

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "KeyStore Migration logic is needed.");
                return -20;

                //// Migrate the in-memory keystore data to the current version.
                //try
                //{
                //    // We will migrate the keystore to a temporary file, and load it.

                //    // Create a temporary folder that we can delete after migration.
                //    stagingfolder = System.IO.Path.Combine(System.IO.Path.GetTempPath(), System.Guid.NewGuid().ToString());
                //    System.IO.Directory.CreateDirectory(stagingfolder);

                //    // If here, we have the staging folder that we will use to store the migrated keystore file.
                //    // So, we need to generate the filepath for the output migrated keystore file.
                //    string migrated_keystorefile_filepath = System.IO.Path.Combine(stagingfolder, "Migrated_KeystoreFile.v2");

                //    // Call the migration method.
                //    if(KeyStore_Migration.Migrate_KeyStore_from_V1_toV2(fpath, migrated_keystorefile_filepath) != 1)
                //    {
                //        // Failed to migrate keystore from V1 to V2.
                //        OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                //            "Failed to migrate keystore from V1 to V2.");

                //        return -7;
                //    }
                //    // If here, the keystore was migrated from V1 to V2.
                //    // We can now load it as a current version keystore.

                //    // Do a recursive load call to load the migrated file (in the current version).
                //    return this.Load(migrated_keystorefile_filepath);
                //}
                //catch (Exception e)
                //{
                //    // Exception occurred while attempting to convert the data section to our key list.
                //    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                //        "Exception occurred while attempting to convert the data section to our key list.");

                //    return -6;
                //}
                //finally
                //{
                //    // Delete the temporary folder that we create above.

                //    try
                //    {
                //        System.IO.Directory.Delete(stagingfolder, true);
                //    }
                //    catch(Exception e)
                //    {

                //    }
                //}
            }
            else
            {
                // The KeystoreVersion of the keystore config does not match this KeystoreVersion of class.
                // It is newer than what we can handle.
                // We will not be able to open it, though, and must throw an error.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "The KeystoreVersion of the keystore config is newer than this application KeystoreVersion can handle. Unable to read keystore.");

                return -6;
            }
        }

        public int Save(out KeyStore_StorageStruct config)
        {
            // Saving the keystore to a config instance is pretty much the reverse of the load method.

            // Create an empty config instance...
            var cfg = new KeyStore_StorageStruct();
            cfg.LastUpdateUTC = this.LastUpdateUTC;
            cfg.CreationDateUTC = this.CreationDateUTC;
            cfg.DataVersion = this.DataVersion;

            // Set the keystore version to ours...
            cfg.KeystoreVersion = KeyStoreVersion;

            // Set the storage keyid...
            cfg.Storage_KeyId = this._storageencryptionkey.KeyName;

            // Populate the data section...
            // This will require copying keys over to a simple list, and serializing the list.
            List<KeyObject_v2> keys = new List<KeyObject_v2>();
            foreach(var k in this._keys.Values)
            {
                keys.Add(k);
            }

            // Convert the key listing to json, so we can encrypt it...
            string jsondata = Newtonsoft.Json.JsonConvert.SerializeObject(keys);

            // Determine if we have a storage key or not...
            if(this._storageencryptionkey == null)
            {
                // No storage key is defined.
                // We cannot encrypt the keystore.

                config = null;
                return -1;
            }
            else
            {
                // The storage encryption key exists.

                // Encrypt our key data using the local AES implementation...
                string encrypteddata = EncryptData(eEncryptionMethods.LocalAES.ToString(), jsondata);
                cfg.KeyData = encrypteddata;

                // Set the storage algorithm...
                cfg.Storage_Algo = eEncryptionMethods.LocalAES.ToString();
            }

            // With the key data set and encrypted, we need to sign the struct.
            // Set the signing method we will be using...
            cfg.Signing_Algo = eSigningMethods.HMACSHA256Signature.ToString();

            // Sign the config...
            var res = Set_KeystoreStruct_Signature(cfg);
            if(res != 1)
            {
                // Failed to sign the config struct.
                config = null;
                return -2;
            }

            config = cfg;
            return 1;
        }

        #endregion


        #region Private Methods

        private int Set_KeystoreStruct_Signature(KeyStore_StorageStruct config)
        {
            try
            {
                if(config == null)
                {
                    // Key store config is null.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        "Key store config is null. Cannot verify keystore struct signature.");

                    return -1;
                }

                // We will use HMACSHA256 for signing.
                // This method uses a symmetric key.
                // Ensure our storage key is compatible.

                // Verify the signing key type...
                if(!this._storageencryptionkey.Is_SymmetricKey())
                {
                    // The storage key is not symmetric.
                    // The storage key type is not correct for signing with it.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        "The storage key type is not correct for signing with it. Cannot verify keystore struct signature.");

                    return -2;
                }
                // Verify the signing keyid and method are in the config...
                config.Storage_KeyId = this._storageencryptionkey.KeyName;
                config.Signing_Algo = eSigningMethods.HMACSHA256Signature.ToString();

                // If the storage key is base64 encoded, we will convert it back to bytes.
                // if the key is NOT base64 encoded, we will convert each ASCII character to a byte.
                byte[] keybytes = new byte[0];
                if(this._storageencryptionkey.IsBase64Encoded)
                {
                    // The key is already base 64 encoded.
                    // We just need to convert it back to bytes.
                    keybytes = Convert.FromBase64String(this._storageencryptionkey.PrivateKey);
                }
                else
                {
                    // Not base 64 encoded.

                    // We will convert the string key byte for byte to binary data...
                    System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
                    keybytes = encoding.GetBytes(this._storageencryptionkey.PrivateKey);
                }

                // Get the bytes of the config data that will be signed...
                byte[] cfgbytes = Concatenate_ConfigProperties_forHashing(config);

                // Compute the signature and stuff it into the config struct...
                config.Signature = Compute_HMACSHA256Hash(keybytes, cfgbytes);

                return 1;
            }
            catch(Exception e)
            {
                // Exception caught during keystore struct signing.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                    "Exception caught during keystore struct signing. Cannot sign keystore struct.");

                return -2;
            }
        }

        private bool Verify_KeystoreStruct_Signature(KeyStore_StorageStruct config)
        {
            try
            {
                string b64computedsignature = "";

                // To verify the keystore signature, we will hash the sensitive parts of the struct together,
                // Create a signature from it, and verify the signatures are a match.

                if(config == null)
                {
                    // Key store config is null.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        "Key store config is null. Cannot verify keystore struct signature.");

                    return false;
                }

                // Get the claimed signature...
                string signature_claim = config.Signature ?? "";
                // Get the signing algo...
                string algo = config.Signing_Algo ?? "";
                string signingkeyid = config.Storage_KeyId ?? "";

                // Determine what signing method we are to use...
                if(string.IsNullOrEmpty(algo))
                {
                    // Signing algo is not set.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        "Keystore signature's signing algorithm is not set. Cannot verify keystore struct signature.");

                    return false;
                }

                if(algo.ToLower().Trim() == eSigningMethods.HMACSHA256Signature.ToString().ToLower())
                {
                    // We are to verify the signature with the HMAC SHA256 signing method.
                    // This method uses a symmetric key.
                    // Ensure our storage key is compatible.

                    // Verify the signing key type...
                    if(!this._storageencryptionkey.Is_SymmetricKey())
                    {
                        // The storage key is not symmetric.
                        // The signing algo type does not match the storage key type.

                        OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                            "The signing algo type does not match the storage key type. Cannot verify keystore struct signature.");

                        return false;
                    }
                    // Verify the signing keyid...
                    if(this._storageencryptionkey.KeyName.ToLower().Trim() != signingkeyid.ToLower().Trim())
                    {
                        // The storage key has a different keyid than what was used to sign the keystore.

                        OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                            "The storage key has a different keyid than what was used to sign the keystore. Cannot verify keystore struct signature.");

                        return false;
                    }

                    // If the key is base64 encoded, we will convert it back to bytes.
                    // if the key is NOT base64 encoded, we will convert each ASCII character to a byte.
                    byte[] keybytes = new byte[0];
                    if(this._storageencryptionkey.IsBase64Encoded)
                    {
                        // The key is already base 64 encoded.
                        // We just need to convert it back to bytes.
                        keybytes = Convert.FromBase64String(this._storageencryptionkey.PrivateKey);
                    }
                    else
                    {
                        // Not base 64 encoded.

                        // We will convert the string key byte for byte to binary data...
                        System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
                        keybytes = encoding.GetBytes(this._storageencryptionkey.PrivateKey);
                    }

                    // Get the bytes of the config data that will be signed...
                    byte[] cfgbytes = Concatenate_ConfigProperties_forHashing(config);

                    // Attempt to compute a signature...
                    b64computedsignature = Compute_HMACSHA256Hash(keybytes, cfgbytes);

                    // Check that the computed and claimed signatures are a match...
                    if(b64computedsignature != signature_claim)
                    {
                        // Signatures do not match.
                        // The keystore data has changed, the signature is bad, or the signing key is bad.

                        OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                            "Keystore signature is different than computed signature. Keystore failed verification.");

                        return false;
                    }
                    // If here, everything passed just fine.

                    return true;
                }
                else
                {
                    // An unknown signing algorithm was used.
                    // We cannot verify the keystore.

                    OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                        $"The keystore was signed by an unknown signing algorithm ({algo ?? ""}). Cannot verify keystore struct signature.");

                    return false;
                }
            }
            catch(Exception e)
            {
                // Exception caught during keystore signature verification.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                    "Exception caught during keystore signature verification. Cannot verify keystore struct signature.");

                return false;
            }
        }

        private byte[] Concatenate_ConfigProperties_forHashing(KeyStore_StorageStruct config)
        {
            // We need to compose a buffer of all the sensitive components of the keystore struct.
            // Easiest way to do this is to iterate its properties, to key value pairs, and concatenate those together.

            // Add each property to a dictionary...
            Dictionary<string, string> props = new Dictionary<string, string>();
            props.Add(nameof(KeyStore_StorageStruct.CreationDateUTC), config.CreationDateUTC.ToString("o"));
            props.Add(nameof(KeyStore_StorageStruct.LastUpdateUTC), config.LastUpdateUTC.ToString("o"));

            props.Add(nameof(KeyStore_StorageStruct.KeyData), config.KeyData);
            props.Add(nameof(KeyStore_StorageStruct.DataVersion), config.DataVersion.ToString());

            props.Add(nameof(KeyStore_StorageStruct.KeystoreVersion), config.KeystoreVersion.ToString());
            props.Add(nameof(KeyStore_StorageStruct.StructVersion), config.StructVersion.ToString());

            props.Add(nameof(KeyStore_StorageStruct.Storage_Algo), config.Storage_Algo);
            props.Add(nameof(KeyStore_StorageStruct.Storage_KeyId), config.Storage_KeyId);
            props.Add(nameof(KeyStore_StorageStruct.Signing_Algo), config.Signing_Algo);


            // Get a list of key value pairings that we can concatenate together...
            var keyValueStrings = props.Select(pair =>
                string.Format("{0}={1}", pair.Key, pair.Value));

            // Concatenate the key value pairs together...
            string kvd = string.Join("&", keyValueStrings);

            // And, convert the data to a byte array...
            var bytes = System.Text.Encoding.UTF8.GetBytes(kvd);

            return bytes;
        }

        private string Compute_HMACSHA256Hash(byte[] key, byte[] bytedata)
        {
            HMACSHA256 hmac = null;

            try
            {
                hmac = new HMACSHA256(key);

                var hb = hmac.ComputeHash(bytedata);

                string b64hash = Convert.ToBase64String(hb);

                return b64hash;
            }
            finally
            {
                hmac?.Dispose();
                hmac = null;
            }
        }

        private string DecryptData(string algo, string keyid, string keyData)
        {
            // Currently, we encrypt the data section using AES256.
            // Check that we were asked to use aes...
            if(algo.ToLower().Trim() != eEncryptionMethods.LocalAES.ToString().ToLower())
            {
                // Encryption method is not a match...
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "The encryption method is not a match. Unable to read keystore.");

                return null;
            }

            // Check that the given keyid is a match as well...
            if(keyid.ToLower().Trim() != this._storageencryptionkey.KeyName.ToLower().Trim())
            {
                // Storage key is not a match.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "The keyid that saved the keystore is not a match. Unable to read keystore.");

                return null;
            }

            // Use AES256 to decrypt the data section...
            string data = NETCore_Common.Crypto.DecryptStringAES(keyData, this._storageencryptionkey.PrivateKey);

            return data;
        }

        /// <summary>
        /// This method encrypts the given data using the given encryption method and storage key.
        /// </summary>
        /// <param name="algo"></param>
        /// <param name="keyData"></param>
        /// <returns></returns>
        private string EncryptData(string algo, string keyData)
        {
            // Currently, we encrypt the data section using AES256.
            // Check that we were asked to use aes...
            if(algo.ToLower().Trim() != eEncryptionMethods.LocalAES.ToString().ToLower())
            {
                // Encryption method is not a match...
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "The encryption method is not a match. Unable to read keystore.");

                return null;
            }

            // Use AES256 to encrypt the data section...
            string data = NETCore_Common.Crypto.EncryptStringAES(keyData, this._storageencryptionkey.PrivateKey);

            return data;
        }

        private bool Have_Algo_for_Keystore(string algo)
        {
            // Currently, we implemenet AES256 for storing keys.
            // Check that the given config was saved with an algorithm we have access to.
            if (algo.ToLower().Trim() == eEncryptionMethods.LocalAES.ToString().ToLower())
                return true;
            else
                return false;
        }

        private bool Have_SigningAlgo_for_Keystore(string algo)
        {
            // Currently, we implemenet HMACSHA256 for signing a keystore.
            // Check that the given config was signed with an algorithm we have access to.
            if (algo.ToLower().Trim() == eSigningMethods.HMACSHA256Signature.ToString().ToLower())
                return true;
            else
                return false;
        }

        private bool Have_StorageKey_for_Keystore(string keyid)
        {
            // Check that the given keystore was encrypted with the same key as our storage key.
            if (keyid.ToLower().Trim() == this._storageencryptionkey.KeyName.ToLower().Trim())
                return true;
            else
                return false;
        }

        #endregion
    }
}
