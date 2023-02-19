using System;
using System.Collections.Generic;
using System.Text;
using OGA.SharedKernel.Extensions.DateandTime;

namespace OGA.KeyMgmt.Model
{
    /// <summary>
    /// This class was derived from the original CryptoKey_v1 in the Licensing Test project for ICore.
    /// 
    /// </summary>
    public class KeyObject_v2
    {
        #region Properties

        public DateTime CreationUTC { get; set; }
        public DateTime LastUpdateUTC { get; set; }

        public string KeyName { get; set; }

        public string KeyType { get; set; }
        public int KeyLength { get; set; }

        public eKeyStatus Status { get; set; }

        /// <summary>
        /// Indicates if the key properties hold Base64 binary data, or not.
        /// If false, the key object is a plain-text password or passphrase.
        /// If true, the key object holds binary data in Base64 format.
        /// </summary>
        public bool IsBase64Encoded { get; set; }

        /// <summary>
        /// This holds the private key (secret key) for both asymmetric and symmetric encryption.
        /// </summary>
        public string PrivateKey { get; set; }
        /// <summary>
        /// This holds the public key for asymmetric encryption.
        /// It is not used for symmetric keys.
        /// </summary>
        public string PublicKey { get; set; }

        public bool PrivEncrypted { get; set; }

        /// <summary>
        /// Set if the private key is contained by this instance.
        /// Always set for symmetric keys.
        /// </summary>
        public bool HasPrivateKey { get; set; }
        /// <summary>
        /// Set if the public key has been calculated and stored in this instance.
        /// Always false for symmetric keys.
        /// </summary>
        public bool HasPublicKey { get; set; }

        /// <summary>
        /// Semicolon delimited list of uses possible with the key object.
        /// Uses can be: signing, encryption, etc.
        /// </summary>
        public string Uses { get; set; }

        #endregion


        #region ctor / dtor

        public KeyObject_v2()
        {
            this.CreationUTC = DateTime.UnixEpoch.ToUniversalTime();
            this.LastUpdateUTC = DateTime.UnixEpoch.ToUniversalTime();

            this.KeyName = "";
            this.KeyType = "";
            this.KeyLength = 0;

            this.Status = eKeyStatus.Unknown;
            this.Uses = "";

            this.IsBase64Encoded = false;

            this.HasPrivateKey = false;
            this.PrivateKey = "";
            this.PrivEncrypted = false;

            this.HasPublicKey = false;
            this.PublicKey = "";
        }

        #endregion


        static public eKeyType Get_KeyType_from_String(string strkeytype)
        {
            if (strkeytype.ToLower().Trim() == "unknown")
                return eKeyType.Unknown;
            else if (strkeytype.ToLower().Trim() == "rsa")
                return eKeyType.RSA;
            else if (strkeytype.ToLower().Trim() == "ecdsa")
                return eKeyType.ECDSA;
            //else if (strkeytype.ToLower().Trim() == "ecdh")
            //    return eKeyType.ECDH;
            else if (strkeytype.ToLower().Trim() == "aes")
                return eKeyType.AES;
            else if (strkeytype.ToLower().Trim() == "password")
                return eKeyType.Password;
            else
                return eKeyType.Unknown;
        }

        static public eKeyStatus Get_KeyStatus_from_String(string strkeystatus)
        {
            if (strkeystatus.ToLower() == "unknown")
                return eKeyStatus.Unknown;
            if (strkeystatus.ToLower() == "enabled")
                return eKeyStatus.Enabled;
            if (strkeystatus.ToLower() == "disabled")
                return eKeyStatus.Disabled;
            else
                return eKeyStatus.Unknown;
        }

        /// <summary>
        /// Makes a copy of the given key instance, but strips out private and public key data.
        /// </summary>
        /// <param name="k"></param>
        public void CopyTo_withoutKeyData(KeyObject_v2 k)
        {
            k.CreationUTC = this.CreationUTC;
            k.LastUpdateUTC = this.LastUpdateUTC;
                
            k.KeyName = this.KeyName;
            k.KeyType = this.KeyType;
            k.KeyLength = this.KeyLength;
            k.Status = this.Status;
            k.Uses = this.Uses;

            // Clear the encoding flag, since no key data will be in the target instance...
            k.IsBase64Encoded = false;

            // Copy over flags that say if a key instance contains private and public data.
            // But, we won't copy over the data in this method.
            k.HasPrivateKey = this.HasPrivateKey;
            k.HasPublicKey = this.HasPublicKey;

            // Don't copy over key data.
            // Leave these unset.
            k.PrivateKey = "";
            k.PublicKey = "";

        }

        /// <summary>
        /// Makes a copy of the given key instance, but strips out private key data.
        /// </summary>
        /// <param name="k"></param>
        public void CopyTo_withoutPrivateData(KeyObject_v2 k)
        {
            k.CreationUTC = this.CreationUTC;
            k.LastUpdateUTC = this.LastUpdateUTC;
                
            k.KeyName = this.KeyName;
            k.KeyType = this.KeyType;
            k.KeyLength = this.KeyLength;
            k.Status = this.Status;
            k.Uses = this.Uses;

            k.IsBase64Encoded = this.IsBase64Encoded;

            // Copy over flags that say if a key instance contains private and public data.
            // But, we won't copy over the public key data in this method.
            k.HasPrivateKey = this.HasPrivateKey;
            k.HasPublicKey = this.HasPublicKey;

            // Copy over public key data, but not private key data.
            k.PrivateKey = "";
            k.PublicKey = this.PublicKey;
        }

        /// <summary>
        /// This method copies all data, including private and public keys.
        /// </summary>
        /// <param name="k"></param>
        public void CopyTo_withKeyData(KeyObject_v2 k)
        {
            k.CreationUTC = this.CreationUTC;
            k.LastUpdateUTC = this.LastUpdateUTC;
                
            k.KeyName = this.KeyName;
            k.KeyType = this.KeyType;
            k.KeyLength = this.KeyLength;
            k.Status = this.Status;
            k.Uses = this.Uses;

            k.IsBase64Encoded = this.IsBase64Encoded;

            // Copy over flags that say if a key instance contains private and public data.
            k.HasPrivateKey = this.HasPrivateKey;
            k.HasPublicKey = this.HasPublicKey;

            // Copy over key data...
            k.PrivateKey = PrivateKey;
            k.PublicKey = this.PublicKey;
        }

        public bool Is_SymmetricKey()
        {
            var ff = Get_KeyType_from_String(this.KeyType);

            // Determine if the key type is a symmetrick key...
            if (ff == eKeyType.AES)
                return true;
            else if (ff == eKeyType.Password)
                return true;
            else
                return false;
        }

        /// <summary>
        /// Used by the keystore to determine if one key will change if updated by properties of another.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public bool CompareTo(KeyObject_v2 key)
        {
            if (key == null)
                return true;

            if (this.CreationUTC != key.CreationUTC)
                return true;
            else if (this.LastUpdateUTC != key.LastUpdateUTC)
                return true;
            else if (this.KeyName != key.KeyName)
                return true;
            else if (this.KeyType != key.KeyType)
                return true;
            else if (this.KeyLength != key.KeyLength)
                return true;
            else if (this.Status != key.Status)
                return true;
            else if (this.Uses != key.Uses)
                return true;
            else if (this.IsBase64Encoded != key.IsBase64Encoded)
                return true;
            else if (this.HasPrivateKey != key.HasPrivateKey)
                return true;
            else if (this.PrivateKey != key.PrivateKey)
                return true;
            else if (this.PrivEncrypted != key.PrivEncrypted)
                return true;
            else if (this.HasPublicKey != key.HasPublicKey)
                return true;
            else if (this.PublicKey != key.PublicKey)
                return true;
            else
                return false;
        }
    }
}
