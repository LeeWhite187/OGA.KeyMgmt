using System;
using System.Collections.Generic;
using System.Text;

namespace OGA.KeyMgmt.Config
{
    /// <summary>
    /// Defines a structure for persisting a set of keys (of a keystore), in JSON format that can be transferred or stored in a larger configuration file.
    /// </summary>
    public class KeyStore_StorageStruct
    {
        static public string CONSTANT_ConfigFile = "config.json";
        static public string CONSTANT_SectionName = "KeyStore_Config";
        static public int Latest_StructVersion = 1;

        public DateTime CreationDateUTC { get; set; }
        public DateTime LastUpdateUTC { get; set; }

        /// <summary>
        /// Contains the version of the keystore data.
        /// This value increments each time a change occurs to the data section.
        /// </summary>
        public int DataVersion { get; set; }

        /// <summary>
        /// The class version of the keystore that created this instance.
        /// </summary>
        public int KeystoreVersion { get; set; }

        /// <summary>
        /// The version of the persisted struct.
        /// </summary>
        public int StructVersion { get; set; }

        /// <summary>
        /// The name of the encryption method used to encrypt keystore header and data sections.
        /// </summary>
        public string Storage_Algo { get; set; }
        /// <summary>
        /// KeyId that was used to encrypt data and sign the keystore.
        /// </summary>
        public string Storage_KeyId { get; set; }

        /// <summary>
        /// Specifies the algorithm used to sign the keystore config.
        /// The storage key can be used for both signing and data encryption.
        /// If the storage key is Symmetric, the signing algorithm is likely HMACSHA256Signature.
        /// If the storage key is Asymmetric, the signing algorithm is probably ECDSA.
        /// </summary>
        public string Signing_Algo { get; set; }

        /// <summary>
        /// Stores a signature (in base64) that can be used to verify the integrity of the contents.
        /// </summary>
        public string Signature { get; set; }

        /// <summary>
        /// Contains the list of stored keys.
        /// This is at-rest encrypted and base-64 encoded.
        /// </summary>
        public string KeyData { get; set; }

        public KeyStore_StorageStruct()
        {
            CreationDateUTC = new DateTime(0);
            LastUpdateUTC = new DateTime(0);
            Storage_Algo = "";
            Storage_KeyId = "";
            Signing_Algo = "";
            DataVersion = 0;
            KeystoreVersion = 0;
            StructVersion = 0;
            KeyData = "";
            Signature = "";
        }
    }
}
