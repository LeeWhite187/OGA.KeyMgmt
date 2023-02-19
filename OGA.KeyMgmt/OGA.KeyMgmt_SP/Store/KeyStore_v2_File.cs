using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using OGA.KeyMgmt.Model;

namespace OGA.KeyMgmt.Store
{
    public class KeyStore_v2_File : KeyStore_v2_JsonConfig
    {
        #region Private Fields

        private string _filepath;

        #endregion


        #region Public Properties

        /// <summary>
        /// Labels the keystore as: memory, json string, file, database, etc...
        /// </summary>
        override public string KeyStoreType { get => "File"; }

        #endregion


        #region ctor / dtor

        /// <summary>
        /// Creates a keystore instance.
        /// </summary>
        public KeyStore_v2_File() : base()
        {
        }

        /// <summary>
        /// Creates a keystore instance. Accepts the path of the offline store.
        /// </summary>
        /// <param name="filepath"></param>
        public KeyStore_v2_File(string filepath) : base()
        {
            this._filepath = filepath;

            // No storage password was given, so we will leave it null.
            _storageencryptionkey = null;
        }

        /// <summary>
        /// Creates a keystore instance. Accepts the path of the offline store and the storage password.
        /// </summary>
        /// <param name="filepath"></param>
        /// <param name="storageencryptionkey"></param>
        public KeyStore_v2_File(string filepath, string storageencryptionkey) : base()
        {
            this._filepath = filepath;

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
        /// Creates a keystore instance. Accepts the path of the offline store and the storage key.
        /// </summary>
        /// <param name="filepath"></param>
        /// <param name="storageencryptionkey"></param>
        public KeyStore_v2_File(string filepath, KeyObject_v2 storageencryptionkey) : base()
        {
            this._filepath = filepath;

            _storageencryptionkey = storageencryptionkey;
        }

        /// <summary>
        /// Creates a keystore instance. Accepts the path of the offline store, storage password, and the associated private key encryption string.
        /// </summary>
        /// <param name="filepath"></param>
        /// <param name="privkey_encryptionkey"></param>
        /// <param name="storageencryptionkey"></param>
        public KeyStore_v2_File(string filepath, string storageencryptionkey, string privkey_encryptionkey) : base(privkey_encryptionkey)
        {
            this._filepath = filepath;

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
        /// Creates a keystore instance. Accepts the path of the offline store, storage key, and the associated private key encryption key.
        /// </summary>
        /// <param name="filepath"></param>
        /// <param name="privkey_encryptionkey"></param>
        /// <param name="storageencryptionkey"></param>
        public KeyStore_v2_File(string filepath, KeyObject_v2 storageencryptionkey, KeyObject_v2 privkey_encryptionkey) : base(privkey_encryptionkey)
        {
            this._filepath = filepath;

            // The caller passed in a storage password as a key.
            _storageencryptionkey = storageencryptionkey;
        }

        #endregion


        #region Storage Methods

        public bool Is_FilePath_Set()
        {
            if (this._filepath != "")
                return true;
            else
                return false;
        }

        public int Load()
        {
            return Load(this._filepath);
        }
        public int Load(string fpath)
        {
            // The raw file is a serialized json object of type, KeyStore.
            // We will deserialize it, verify its signature, and load its keys.

            OGA.KeyMgmt.Config.KeyStore_StorageStruct cfgstruct = null;

            OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                "Checking if key store file exists...");

            // Check that the key file exists.
            if (!System.IO.File.Exists(fpath))
            {
                // File doesn't exist.
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Key store file not found.");

                return -1;
            }

            OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                "Candidate key store file found.");

            // Attempt to read and deserialize the file data into our storage struct...
            try
            {

                var rawdata = System.IO.File.ReadAllText(fpath, System.Text.Encoding.UTF8);

                cfgstruct = Newtonsoft.Json.JsonConvert.DeserializeObject<OGA.KeyMgmt.Config.KeyStore_StorageStruct>(rawdata);

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                    "Read raw data from candidate key store file.");
            }
            catch (Exception)
            {
                // Failed to read in data from the file.
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Failed to read in data from file.");

                return -2;
            }
            // If here, we loaded the config struct.
            // We can now call the load struct method to pull in the keystore.

            return Load(cfgstruct);
        }

        public int Save()
        {
            return Save(this._filepath);
        }
        public int Save(string fpath)
        {
            // We will first create the config struct that will be serialized to the file...
            var res = Save(out var config);
            if(res != 1)
            {
                // Failed to store keystore in config struct.

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Failed to store keystore in config struct. We cannot save it to disk.");

                return -1;
            }
            // If here, the keystore has been stuffed into a config struct.
            // We can serialize it to disk.

            try
            {
                var jsonstring = Newtonsoft.Json.JsonConvert.SerializeObject(config);

                System.IO.File.WriteAllText(fpath, jsonstring);

                // If here, the file was saved.
                return 1;
            }
            catch (Exception e)
            {
                // Exception occurred while attempting to save the key store to a file.
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(e,
                    "Exception occurred while attempting to save the key store to a file.");

                return -2;
            }
        }

        static public int Get_Version_of_KeyStoreFile(string filepath)
        {
            OGA.KeyMgmt.Config.KeyStore_StorageStruct cfgstruct = null;

            OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                "Checking if key store file exists...");

            // Check that the key file exists.
            if (!System.IO.File.Exists(filepath))
            {
                // File doesn't exist.
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Key store file not found.");

                return -1;
            }

            OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                "Candidate key store file found.");

            // Attempt to read and deserialize the file data into our storage struct...
            try
            {

                var rawdata = System.IO.File.ReadAllText(filepath, System.Text.Encoding.UTF8);

                cfgstruct = Newtonsoft.Json.JsonConvert.DeserializeObject<OGA.KeyMgmt.Config.KeyStore_StorageStruct>(rawdata);

                OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                    "Read raw data from candidate key store file.");
            }
            catch (Exception)
            {
                // Failed to read in data from the file.
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Failed to read in data from file.");

                return -2;
            }
            // If here, we loaded the config struct.

            int ver = cfgstruct.KeystoreVersion;
            if (ver <= 0)
            {
                // Failed to recover the version from the candidate key store file.
                OGA.SharedKernel.Logging_Base.Logger_Ref?.Error(
                    "Failed to recover the version from the candidate key store file.");

                return -4;
            }

            OGA.SharedKernel.Logging_Base.Logger_Ref?.Info(
                "Version recovered from key store file. Version is {0}", ver.ToString());

            return ver;
        }

        #endregion


        #region Private Methods

        #endregion
    }
}
