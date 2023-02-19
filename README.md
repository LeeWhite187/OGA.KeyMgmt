# OGA.KeyMgmt
Simple Key Manager with persistence to Json or file

## Description
This library contains an in-memory (and persistable) keystore for processes that need to use or share encryption keys.

## Features
A keystore instance supports the generation, verification, usage, and persistence of encryption keys of: RSA, AES, and ECDSA.\
It currently leverages base .NET encryption libraries. But, can be extended to create keys in Bouncy Castle or LibSodium.\
A persisted keystore is versioned, so that it can be correctly loaded by a newer keystore class version.\
A keystore also updates a version counter each time its contents are changed, for easier reconciliation.\
A persisted keystores can be signed (via ECDSA) to ensure integrity and tampering. It signature is verified on load.\
Keys can be retrieved from the store by name, or by predicate filter ([See PredicateBuilder](https://github.com/LeeWhite187/OGA.DomainBase/blob/main/OGA.DomainBase/OGA.DomainBase_SP/QueryHelpers/PredicateBuilder.cs))


## Installation
OGA.DomainBase is available via NuGet:
* NuGet Official Releases: [![NuGet](https://img.shields.io/nuget/vpre/OGA.DomainBase.svg?label=NuGet)](https://www.nuget.org/packages/OGA.DomainBase)

## Dependencies
This library depends on:
* [OGA.SharedKernel](https://github.com/LeeWhite187/OGA.SharedKernel)
* [NewtonSoft.Json](https://github.com/JamesNK/Newtonsoft.Json)
* [NLog](https://github.com/NLog/NLog/)

## Building OGA.DomainBase
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
