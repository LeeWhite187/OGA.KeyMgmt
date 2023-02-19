using System;
using System.Collections.Generic;
using System.Text;

namespace OGA.KeyMgmt.Helper
{
    public class Conversions
    {
        /// <summary>
        /// This function converts a string to a byte array.
        /// </summary>
        /// <param name="In_String"></param>
        /// <returns></returns>
        static public byte[] String_to_Byte(string In_String)
        {
            if (string.IsNullOrEmpty(In_String))
                return new byte[0];

            System.Text.ASCIIEncoding enc = new ASCIIEncoding();
            return enc.GetBytes(In_String);
        }
    }
}
