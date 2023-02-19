using System;
using System.Collections.Generic;
using System.Text;

namespace OGA.KeyMgmt.Model
{
    public enum eSigningMethods
    {
        // Unknown signing method
        Unknown = 0,
        // ECC Digital signing Algorithm.
        ECDSA = 1,
        // HMACSHA256 Signature.
        HMACSHA256Signature = 2,
    }

    public enum eEncryptionMethods
    {
        // Unknown signing method
        Unknown = 0,
        // Local .NET AES256 with string-based key.
        LocalAES = 1,
        // RSA
        RSA = 2,
    }

    public enum eKeyType
    {
        // Unknown key type
        Unknown = 0,
        // Asymmetric key type.
        RSA = 1,
        // Asymmetric key type.
        ECDSA = 2,
        // Symmetric key type.
        AES = 3,
        // Password
        Password = 4
        //// Asymmetric key type.
        //ECDH = 5
    }

    public enum eKeyStatus
    {
        Unknown = 0,
        Enabled = 1,
        Disabled = 2
    }
}
