using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using OGA.KeyMgmt.Model;

namespace OGA.KeyMgmt.Store
{
    /// <summary>
    /// Memory-backed keystore, used to hold keys that are passed in from other sources, or for testing.
    /// </summary>
    public class KeyStore_v2_Mem : KeyStore_v2_Base
    {
        #region Private Fields

        #endregion


        #region Public Properties

        /// <summary>
        /// Labels the keystore as: memory, json string, file, database, etc...
        /// </summary>
        override public string KeyStoreType { get => "Memory"; }

        #endregion


        #region ctor / dtor

        /// <summary>
        /// Creates a keystore instance. This class type is memory-based, with no persistent backing store.
        /// </summary>
        public KeyStore_v2_Mem() : base()
        {
        }

        #endregion
    }
}
