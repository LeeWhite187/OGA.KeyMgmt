# OGA.KeyMgmt
Simple Key Manager with persistence to Json or file

## Description
This library contains an in-memory (and persistable) keystore for processes that need to use or share encryption keys.
It can be used as a process-wide, in-memory keystore, that holds keys, retrieved from a central secret authority.
Or, it can manage keys that are stored in JSON or a file (saved in JSON format).

## Features
The following is a list of key object and keystore features:
* A keystore instance supports the generation, verification, usage, and persistence of encryption keys of:
  * RSA
  * AES
  * ECDSA
* It currently leverages base .NET encryption libraries. But, can be extended to create keys in Bouncy Castle or LibSodium.
* Supports CRUD functionality of key objects.
* Key objects can be retrieved from the store by name or by key properties, such as type, age, status, etc...
* Key queries are implemented using a predicate filter (See comments at top of [PredicateBuilder](https://github.com/LeeWhite187/OGA.DomainBase/blob/main/OGA.DomainBase/OGA.DomainBase_SP/QueryHelpers/PredicateBuilder.cs)).
* Both key object and keystore classes are versioned, so they can be correctly loaded by (and migrated to) newer versions.
* A keystore updates a version counter each time its contents are changed, for easier reconciliation.
* Persisted keystores are signed (via ECDSA) to ensure integrity and tampering. The signature is verified on load.
* At-rest encryption is used for securely storing private keys.

## Installation
OGA.KeyMgmt is available via NuGet:
* NuGet Official Releases: [![NuGet](https://img.shields.io/nuget/vpre/OGA.KeyMgmt.svg?label=NuGet)](https://www.nuget.org/packages/OGA.KeyMgmt)

## Dependencies
This library depends on:
* [OGA.SharedKernel](https://github.com/LeeWhite187/OGA.SharedKernel)
* [NewtonSoft.Json](https://github.com/JamesNK/Newtonsoft.Json)
* [NLog](https://github.com/NLog/NLog/)

## Usage
Here is some usage examples.
Creating in-memory keystore with new keys:
```
            // Create three keys...
            KeyStore_v2_Base.Create_New_AES_Key(Guid.NewGuid().ToString(), 256, out var k2);
            KeyStore_v2_Base.Create_New_ECDSA_KeyPair(Guid.NewGuid().ToString(), out var k3);
            KeyStore_v2_Base.Create_New_RSA_KeyPair(Guid.NewGuid().ToString(), 512, out var k4);

            // Add all three keys to a new in-memory keystore instance...
            var ks = new KeyStore_v2_Base();
            var res1 = ks.AddKey_toStore(k1);
            var res2 = ks.AddKey_toStore(k2);
            var res3 = ks.AddKey_toStore(k3);
```
* Key Object - Holds a single encryption key and metadata. For asymmetric keys, can contain both private and public key data.
* Key Store - Manages a collection of key objects using CRUD and predicate filter query functionality.\

```
code blocks for commands
```

* 

## Building OGA.KeyMgmt
This library is built with the new SDK-style projects.
It contains multiple projects, one for each of the following frameworks:
* NET 5
* NET 6

And, the output nuget package includes runtimes targets for:
* linux-64
* win-x64

## Framework and Runtime Support
Currently, the nuget package of this library supports the framework versions and runtimes of applications that I maintain (see above).
If someone needs others (older or newer), let me know, and I'll add them to the build script.

## Visual Studio
It is currently built using Visual Studio 2019 17.1.

## License
Please see the [License](LICENSE).
