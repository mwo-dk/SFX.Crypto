# SFX.Crypto
Wrapping of various facilities from ```System.Security.Cryptography``` utilizing [SFX.ROP](https://www.nuget.org/packages/SFX.ROP/) and [SFX.ROP.CSharp](https://www.nuget.org/packages/SFX.ROP.CSharp/)

## Usage C#

The are two C# packages:

* [SFX.Crypto.CSharp](https://www.nuget.org/packages/SFX.Crypto.CSharp/) contains classes, that facilitate hashing, encryption/decryption and signing facilities that should work on all .Net core supported platforms.
* [SFX.Crypto.Windows.CSharp](https://www.nuget.org/packages/SFX.Crypto.Windows.CSharp/) contains classes, that facilitate hashing, encryption/decryption and signing facilities that should work on windows only.

### Hashing

Hashing is supported by the ```HashService``` class, that lives in the namespace ```SFX.Crypto.CSharp.Infrastructure.Hashing```. It implements the interface ```IHashService```, that has the signature:

``` csharp
public interface IHashService
{
    Result<IHash> ComputeHash(IPayload payload);
}
```

Where the two *model* types ```IHash``` and ```IPayload``` are simple placeholders of byte arrays:

``` csharp
public interface IHash : IValidatable
{
    byte[] Value { get; }
}
```

and ```Result<>``` is discussed in the [SFX.ROP](https://github.com/mwo-dk/SFX.ROP) repository. The packages contain a lot of byte array holders, with different names, since we insist knowledge of context in where a given byte array is utilized. 

While at it, most of not all extend/implement ```IValidatable```:

``` csharp
public interface IValidatable
{
    bool IsValid();
}
```

which require no further explanation.

In order to invoke ```ComputeHash```, the service needs to be built, that is to let it know which hashing algorithm to utilize, which is where the builder-like member methods come into play:

* ```WithSHA1CryptoServiceProvider() -> HashService``` tells the ```HashService``` to utilize [```SHA1CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha1cryptoserviceprovider?view=netframework-4.8) hashing.
* ```WithSHA1Managed() -> HashService``` tells the ```HashService``` to utilize [```SHA1Managed```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha1managed?view=netframework-4.8) hashing.
* ```WithSHA256CryptoServiceProvider() -> HashService``` tells the ```HashService``` to utilize [```SHA256CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256cryptoserviceprovider?view=netframework-4.8) hashing.
* ```WithSHA256Managed() -> HashService``` tells the ```HashService``` to utilize [```SHA256Managed```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256managed?view=netframework-4.8) hashing.
* ```WithSHA384CryptoServiceProvider() -> HashService``` tells the ```HashService``` to utilize [```SHA256CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha384cryptoserviceprovider?view=netframework-4.8) hashing.
* ```WithSHA384Managed() -> HashService``` tells the ```HashService``` to utilize [```SHA384Managed```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha384managed?view=netframework-4.8) hashing.
* ```WithSHA512CryptoServiceProvider() -> HashService``` tells the ```HashService``` to utilize [```SHA512CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha512cryptoserviceprovider?view=netframework-4.8) hashing.
* ```WithSHA512Managed() -> HashService``` tells the ```HashService``` to utilize [```SHA512Managed```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha512managed?view=netframework-4.8) hashing.
* ```WithMD5CryptoServiceProvider() -> HashService``` tells the ```HashService``` to utilize [```MD5CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.md5cryptoserviceprovider?view=netframework-4.8) hashing.

#### Intended use

Set up the hash service instance **once** to utilize whatever algorithm fits your needs. The builder methods will replace an existing algorithm instance **and** dispose it. This means that combinations of changing algorithms and computing hashes on the same instance in a multithreaded environment will not be working very well unless you yourself utilize some locking mechanism to avoid hazards.

```HashService``` is ```IDisposable```, hence it cleans up the utilized algorithm upon disposal, and thus throws ```ObjectDisposedExceptions``` in case of attempt to invoke methods on it after disposal.

### Encryption and decryption

Encryption and decryption is facilitated via symmetric (Aes) as well as asymmetric (RSA) services. They are named identically and have similarly named models (byte-array holders), but are different types. The are constructed very similarly, that is:

* They support encryption as well as decryption.
* The require set up, that is which implementation of the given algorithm is required.
* For both, extra build up methods have been provided in the [SFX.Crypto.Windows.CSharp](https://www.nuget.org/packages/SFX.Crypto.Windows.CSharp/) package, that has the Windows-only Cng implementations baked in.
* For both, intended use is, that wire-up wrt algorithms et al should be done before first use and then never again.

#### Asymetric
At the moment only RSA-kind services have been provided for. Also PKCS1-padding has been hard-wired, and will stay so, till it will no longer, ie. in case of street riots, walls of shame filled with complaints thereof and the like.

Support for Elliptic Curve DiffieHellman will be inserted later on in the Windows only package. 

##### (I)CryptoService

Encryption is supported by the type ```CryptoService``` in the namespace ```SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes``` and implements the interface ```ICryptoService```:

``` csharp
public interface ICryptoService
{
    Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload);
    Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload);
}
```

Where the parameeters should be very obvious (the extend ```IValidatable```). 

In order to utilize the service, it has to be initialized with one of:

* ```WithRSACryptoServiceProvider() -> CryptoService``` tells the ```CryptoService``` to utilize the standard [```RSACryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=netframework-4.8).
* ```WithRSACng() -> CryptoService``` tells the ```CryptoService``` to utilize the standard [```RSACng```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacng?view=netframework-4.8).

Besides this - and **after** setting up the algorithm, in order to perform a successful encryption, the method ```WithEncryptionKey(IEncryptionKey) -> CryptoService``` has to be invoked. The ```IEncryptionKey``` must be a public key, what works with the algorithm set up. Similarly - and **after** setting up the algorithm, in order to perform a successful decryption, the method ```WithDecryptionKey(IDecryptionKey) -> CryptoService``` has to be invoked. The ```IDecryptionKey``` must be a private key, what works with the algorithm set up.

This "clumsy" ceremonic way of setting up in steps before usage and then never again is by design in order not to:

* Have to lock around multiple methods.
* Carry around encryption- and decryption keys.

##### RandomKeyPairProvider

In case pubic and private keys for the RSA-based ```CryptoService``` are required, the helper class ```RandomKeyPairProvider``` has been provided for. ```RandomKeyPairProvider``` implements ```IRandomKeyPairProvider<EncryptionKey, DecryptionKey>```:

``` csharp
public interface IRandomKeyPairProvider<PUBLICKEY, PRIVATEKEY>
{
    Result<(PUBLICKEY PublicKey, PRIVATEKEY PrivateKey)> GenerateKeyPair();
}
```

```RandomKeyPairProvider``` must be initialized with the extension method: 

``` csharp
public static class RandomKeyPairProviderExtensions
{
    public static Service WithAlgorithm<Service, PublicKey, PrivateKey>(this Service service,
        System.Security.Cryptography.RSA algorithm)
        where Service : RandomKeyPairProviderBase<PublicKey, PrivateKey>
    {
        service.Algorithm = algorithm;
        return service;
    }
}
```

Which should require no further explanation. The reason a different design choice has been taken here is, that an extension method has been preferred in order to re-utilize it with the similar (identical actually) implementation for the ```SignatureService```.

#### Symmetric

For symmetric encryption, only Aes-kind of algorithms have been provided. Padding and mode have been hard-wired to PKCS7 and CBC respectively - for the moment. Things can be modified if either the honorable Bill Clinton **did** have sex with that woman or if Gretha Thunberg looks angry at me and once again shouts "How DARE YOU" while staring at me with those eyes that makes me generally worried.

##### (I)CryptoService

Encryption is supported by the type ```CryptoService``` in the namespace ```SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes``` and implements the interface ```ICryptoService```:

``` csharp
public interface ICryptoService
{
    Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload);
    Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload);
}
```

Where the parameeters should be very obvious (the extend ```IValidatable```). 

In order to utilize the service, it has to be initialized with one of:

* ```WithAesCryptoServiceProvider() -> CryptoService``` tells the ```CryptoService``` to utilize the standard [```AesCryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aescryptoserviceprovider?view=netframework-4.8).
* ```WithAesManaged() -> CryptoService``` tells the ```CryptoService``` to utilize the standard [```AesManaged```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesmanaged?view=netframework-4.8).
* ```WithAesCng() -> CryptoService``` tells the ```CryptoService``` to utilize the standard [```AesCng```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aescng?view=netframework-4.8).

Besides this - and **after** setting up the algorithm, in order to perform a successful encryption or decryption, the method ```WithSecret(ISecret) -> CryptoService``` and ```WithSalt(ISalt) -> CryptoService``` both have to be invoked. 

This "clumsy" ceremonic way of setting up in steps before usage and then never again is by design in order not to:

* Have to lock around multiple methods.
* Carry around encryption- and decryption keys.

##### RandomSecretAndSaltProvider

Similar to the ```RandomKeyPairProvider``` for RSA, we have a ```RandomSecretAndSaltProvider```, that implements:

``` csharp
public interface IRandomSecretAndSaltProvider
{
    Result<(ISecret Secret, ISalt Salt)> GenerateKeyPair();
}
```

That similar to the above must be initialized with one of the following:

* ```WithAesCryptoServiceProvider -> CryptoService```,
* ```WithAesManaged -> CryptoService``` or
* ```WithAesCng -> CryptoService``` (available in the Windows package)

### Signing

Lastly we have to ```SignatureService```, that is utilized to sign or verify data or hashes thereof. ```SignatureService``` implements ```ISignatureService```:

``` csharp
public interface ISignatureService
{
    Result<ISignature> SignPayload(IPayload payload);
    Result<ISignature> SignHash(IHash hash);
    Result<bool> VerifyPayload(IPayload payload, ISignature signature);
    Result<bool> VerifyHash(IHash hash, ISignature signature);
}
```

Where again the verious model types are byte-array holders, that implement ```IValidatable```. The ```SignatureService``` utilizes ```RSACryptoServiceProvider``` behind the scenes, but has to be initialized with respect to:

* Hash algorithm. One of the methods ```WithSHA1```,  ```WithHA256```, ```WithSHA384```, ```WithSHA512```or ```WithMD5``` need to be invoked (again: **once** before first invokation). The methods have the signature ```unit/void -> SignatureService```.
* Signature padding. One of the methods ```WithPkcs1``` or ```WithPss``` must be invoked, and the reason should be clear.
* Signing and verification keys must also be provided, and these must be a valid public and private key pair for the ```RSACryptoServiceProvider```. These keys are set up via the methods ```WithSigningKey``` and ```WithVerificationKey``` respectively.

#### RandomKeyPairProvider

Similar to the asymmetric encryption and decryption scenario, an identical key pair provider class has been provded. It is also named ```RandomKeyPairProvider``` and lives in the same namespace as the ```SignatureService```.

## Usage F#

The above facities have also been provided for for F#. The are two C# packages:

* [SFX.Crypto](https://www.nuget.org/packages/SFX.Crypto/) contains modules, that facilitate hashing, encryption/decryption and signing facilities that should work on all .Net core supported platforms.
* [SFX.Crypto.Windows](https://www.nuget.org/packages/SFX.Crypto.Windows/) contains modules, that facilitate hashing, encryption/decryption and signing facilities that should work on windows only.

As above, we'll discuss them interchangably, where utilization of Cng algorithms imply that the Windows package (that depends on the common package) is added.

### Hashing

Hashing of data, is supported in the module ```SFX.Crypto.Hashing``` and sub-modules. To make things brief and not too repeatable, we simply iterate through the modules, function by function.

#### SFX.Crypto.Hashing

This is the parent module for all hashing, with the following types declared:

* ```Payload``` a record, that has a single property ```Value```, that is byte-array. It represents a payload to be hashed.
* ```Hash``` another record with the same shape as ```Payload```. It represents a hash of a ```Payload```.

That is: 

``` fsharp
type Payload = {Value: byte array}
type Hash = {Value: byte array}
```

Besides the types denoted above, this module also contains a set of functions:

* ```createService: unit -> HashService```, creates a new ```HashService```
* ```withSHA1CryptoServiceProvider: HashService -> HashService```, sets up the provided service th utilize the [```SHA1CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha1cryptoserviceprovider?view=netframework-4.8) algorithm for hashing.
* ```withSHA1Managed: HashService -> HashService```, sets up the provided service th utilize the [```SHA1Managed```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha1managed?view=netframework-4.8) algorithm for hashing.
* ```withSHA256CryptoServiceProvider: HashService -> HashService```, sets up the provided service th utilize the [```SHA256CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256cryptoserviceprovider?view=netframework-4.8) algorithm for hashing.
* ```withSHA256Managed: HashService -> HashService```, sets up the provided service th utilize the [```SHA256Managed```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256managed?view=netframework-4.8) algorithm for hashing.
* ```withSHA384CryptoServiceProvider: HashService -> HashService```, sets up the provided service th utilize the [```SHA384CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha384cryptoserviceprovider?view=netframework-4.8) algorithm for hashing.
* ```withSHA384Managed: HashService -> HashService```, sets up the provided service th utilize the [```SHA384Managed```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha384managed?view=netframework-4.8) algorithm for hashing.
* ```withSHA512CryptoServiceProvider: HashService -> HashService```, sets up the provided service th utilize the [```SHA512CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha512cryptoserviceprovider?view=netframework-4.8) algorithm for hashing.
* ```withSHA512Managed: HashService -> HashService```, sets up the provided service th utilize the [```SHA512Managed```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha512managed?view=netframework-4.8) algorithm for hashing.
* ```withMD5CryptoServiceProvider: HashService -> HashService```, sets up the provided service th utilize the [```MD5CryptoServiceProvider```](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.md5cryptoserviceprovider?view=netframework-4.8) algorithm for hashing.
* ```computeHash: Payload -> HashService -> Result<Hash,exn>``` the main function to be utilized after setup.

A typical utilization example could be:

``` fsharp
open SFX.Crypto.Hashing

use service = createService() |> withSHA512CryptoServiceProvider
....
let payload = computeThatPayload()

match service |> computeHash payload with 
| Success hash -> hash |> useTheHashForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

That is the service is an ```IDisposable``` entity so use the ```use``` binding instead of the ```let```

##### SFX.Crypto.Hashing.Default

The ```Default``` sub-module is just a simplicication, that removes one argument (the ```HashService```) in the parent module, since it hosts a shared/static instance of one, so utilization similar to the one above could be:

``` fsharp
open SFX.Crypto.Hashing.Default

do withSHA512CryptoServiceProvider()
....
let payload = computeThatPayload()

match payload |> computeHash with 
| Success hash -> hash |> useTheHashForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

This also means, that if this module is utilized, the same care should be taken regarding changing algorithms etc.

### Encryption and decryption

As with the discussion about C#, we also have two types of encryption and decryption, namely RSA-based asymmetric as well as Aes-based symmetric crypto services, which are all wrapped in the module ```SFX.Crypto.Encryption```.

#### Asymmetric

Everthing RSA-based is sitting inside the modules ```SFX.Crypto.Encryption.Asymmetric.RSA``` and ```SFX.Crypto.Windows.Encryption.Asymmetric.RSA```:

##### SFX.Crypto.Encryption.Asymmetric.RSA

In this module, the two record types ```EncryptionKey``` as well as ```DecryptionKey´`` are defined and we have no variation in standard: they are simple byte array holders:

``` fsharp
type EncryptionKey = {Value: byte array}
type DecryptionKey´ = {Value: byte array}
```

###### SFX.Crypto.Encryption.Asymmetric.RSA.Data

This module adresses the features, that regard standard encryption and decryption utilizing various out of the box RSA-type algorithms. It therefore defines two record types named ```UnencryptedPayload``` and ```EncryptedPayload```, that have the following surprising signatures:

``` fsharp
type UnencryptedPayload = {Value: byte array}
type EncryptedPayload = {Value: byte array}
```

This should not be too shocking to most readers. Besides this, the following functions are exposed to the universe, for everyone to invoke as often as they please:

* ```createService: unit -> CryptoService```, creates a new (```IDisposable```) ```CryptoService``` instance.
* ```withRSACryptoServiceProvider: CryptoService -> CryptoService```, wires the provided ```CryptoService``` to utilize ```RSACryptoServiceProvider```.
* ```withEncryptionKey: EncryptionKey -> CryptoService -> CryptoService```, sets the provided ```CryptoService``` to utilize the provided (public) key for encryption.
* ```withDecryptionKey: DecryptionKey -> CryptoService -> CryptoService```, sets the provided ```CryptoService``` to utilize the provided (private) key for decryption.
* ```encrypt: UnencryptedPayload -> CryptoService -> Result<EncryptedPayload, exn>```, does the actual encryption of the payload provided.
* ```decrypt: EncryptedPayload -> CryptoService -> Result<DecryptedPayload, exn>```, does the actual decryption of the payload provided.

The same concerns as for the C# edition applies: set up things once and then run. Do not change algorithms or keys on the fly for a service instance especially in a multi-threaded environment. 

This the Windows-only package has an additional module named ```SFX.Crypto.Windows.Encryption.Asymmetric.RSA.Data```, where the function is defined:

* ```withRSACng: CryptoService -> CryptoService```, wires the provided ```CryptoService``` to utilize the ```RSACng``` algorithm.

So a basic example to encrypt/decrypt paylods could be:

``` fsharp
open SFX.Crypto.Encryption.Asymmetric.RSA.Data

let publicKey = getThatPublicKey()
let privateKey = getThatPrivateKey()
use service = 
    createService() |> 
    withRSACryptoServiceProvider |>
    withEncryptionKey publicKey |>
    withDecryptionKey privateKey
....
let payload = computeThatPayload()

match service |> encrypt payload with 
| Success encryptedData -> encryptedData |> useTheEncryptedPayloadForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

And similarly for decryption.

###### SFX.Crypto.Encryption.Asymmetric.RSA.Key

This module facilitate generation of random key pairs for RSA-type algorithms via:

* ```createKeyPairProvider: unit -> RandomKeyPairProvider```, creates a ```RandomKeyPairProvider```.
* ```withRSACryptoServiceProvider: RandomKeyPairProvider -> RandomKeyPairProvider```, sets up the provided ```RandomKeyPairProvider``` to  utilize```RSACryptoServiceProvider```. This is fairly redundant, since the ```RandomKeyPairProvider``` is pre-cooked in this mode.
* ```generateKeyPair: RandomKeyPairProvided -> Result<(EncryptionKey*DecryptionKey),exn>```, gives you the public and private keys for the algorithm utilized

This the Windows-only package has an additional module named ```SFX.Crypto.Windows.Encryption.Asymmetric.RSA.Key```, where the function is defined:

* ```withRSACng: CryptoService -> CryptoService```, wires the provided ```CryptoService``` to utilize the ```RSACng``` algorithm.

An example of utilizing this could be:

``` fsharp
open SFX.Crypto.Encryption.Asymmetric.RSA.key

use provider = createKeyPairProvider() |> withRSACryptoServiceProvider

match provider |> generateKeyPair with 
| Success (publicKey, privateKey) -> 
    publicKey |> useThePublicKeyForWhatever
    privateKey |> useThePrivateKeyForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

As with the example for hashing, we have modules under the ```Default``` sub-module, that hides a static instance of the services and providers mentioned,

###### SFX.Crypto.Encryption.Asymmetric.RSA.Default.Data

Enables a simpler encryption/decryption example like:

``` fsharp
open SFX.Crypto.Encryption.Asymmetric.RSA.Data
open SFX.Crypto.Encryption.Asymmetric.RSA.Default.Data

let publicKey = getThatPublicKey()
let privateKey = getThatPrivateKey()
do  withRSACryptoServiceProvider() |>
    withEncryptionKey publicKey |>
    withDecryptionKey privateKey |> 
    ignore
....
let payload = computeThatPayload()

match payload |> encrypt with 
| Success encryptedData -> encryptedData |> useTheEncryptedPayloadForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

And similarly for key pair generation we have

###### SFX.Crypto.Encryption.Asymmetric.RSA.Default.Key

``` fsharp
open SFX.Crypto.Encryption.Asymmetric.RSA.key
open SFX.Crypto.Encryption.Asymmetric.RSA.Default.key

do withRSACryptoServiceProvider() |> ignore

match generateKeyPair() with 
| Success (publicKey, privateKey) -> 
    publicKey |> useThePublicKeyForWhatever
    privateKey |> useThePrivateKeyForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

#### Symmetric

Everthing Aes-based is sitting inside the modules ```SFX.Crypto.Encryption.Symmetric.Aes``` and ```SFX.Crypto.Windows.Encryption.Symmetric.Aes```:

##### SFX.Crypto.Encryption.Symmetric.Aes

In this module, the two record types ```Secret``` as well as ```Salt`` are defined and we have no variation in standard: they are simple byte array holders.

``` fsharp
type Secret = {Value: byte array}
type Salt = {Value: byte array}
```

###### SFX.Crypto.Encryption.Symmetric.Aes.Data

This module adresses the features, that regard standard encryption and decryption utilizing various out of the box Aes-type algorithms. It therefore defines two record types named ```UnencryptedPayload``` and ```EncryptedPayload```, that have the following surprising signatures:

``` fsharp
type UnencryptedPayload = {Value: byte array}
type EncryptedPayload = {Value: byte array}
```

Besides this, the following functions are exposed to the universe, for everyone to invoke as often as they please:

* ```createService: unit -> CryptoService```, creates a new (```IDisposable```) ```CryptoService``` instance.
* ```withAesCryptoServiceProvider: CryptoService -> CryptoService```, wires the provided ```CryptoService``` to utilize ```AesCryptoServiceProvider```.
* ```withAesManaged: CryptoService -> CryptoService```, wires the provided ```CryptoService``` to utilize ```AesAesManaged```.
* ```withSecret: Secret -> CryptoService -> CryptoService```, sets the provided ```CryptoService``` to utilize the provided secret for encryption.
* ```withSalt: Salt -> CryptoService -> CryptoService```, sets the provided ```CryptoService``` to utilize the provided salt for decryption.
* ```encrypt: UnencryptedPayload -> CryptoService -> Result<EncryptedPayload, exn>```, does the actual encryption of the payload provided.
* ```decrypt: EncryptedPayload -> CryptoService -> Result<DecryptedPayload, exn>```, does the actual decryption of the payload provided.

The same concerns as for the C# edition applies: set up things once and then run. Do not change algorithms or keys on the fly for a service instance especially in a multi-threaded environment. 

This the Windows-only package has an additional module named ```SFX.Crypto.Windows.Encryption.Symmetric.Aes.Data```, where the function is defined:

* ```withAesCng: CryptoService -> CryptoService```, wires the provided ```CryptoService``` to utilize the ```AesCng``` algorithm.

So a basic example to encrypt/decrypt paylods could be:

``` fsharp
open SFX.Crypto.Encryption.Symmetric.Aes.Data

let secret = getThatSecret()
let salt = getThatSalt()
use service = 
    createService() |> 
    withAesCryptoServiceProvider |>
    withSecret secret |>
    withSalt salt
....
let payload = computeThatPayload()

match service |> encrypt payload with 
| Success encryptedData -> encryptedData |> useTheEncryptedPayloadForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

And similarly for decryption.

###### SFX.Crypto.Encryption.Symmetric.Aes.Key

This module facilitate generation of random key pairs for Aes-type algorithms via:

* ```createKeyPairProvider: unit -> RandomSecretAndSaltProvider```, creates a ```RandomSecretAndSaltProvider```.
* ```withAesCryptoServiceProvider: RandomSecretAndSaltProvider -> RandomSecretAndSaltProvider```, sets up the provided ```RandomSecretAndSaltProvider``` to utilize ```AesCryptoServiceProvider```. This is fairly redundant, since the ```RandomSecretAndSaltProvider``` is pre-cooked in this mode.
* ```withAesManaged: RandomSecretAndSaltProvider -> RandomSecretAndSaltProvider```, sets up the provided ```RandomSecretAndSaltProvider``` to utilize ```AesManaged```.
* ```generateKeyPair: RandomKeyPairProvided -> Result<(Secret*Salt),exn>```, gives you the public and private keys for the algorithm utilized

This the Windows-only package has an additional module named ```SFX.Crypto.Windows.Encryption.Symmetric.Aes.Key```, where the function is defined:

* ```withAesCng: CryptoService -> CryptoService```, wires the provided ```CryptoService``` to utilize the ```AesCng``` algorithm.

An example of utilizing this could be:

``` fsharp
open SFX.Crypto.Encryption.Symmetric.Aes.key

use provider = createKeyPairProvider() |> withAesCryptoServiceProvider

match provider |> generateKeyPair with 
| Success (secret, salt) -> 
    secret |> useTheSecretForWhatever
    salt |> useTheSaltForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

As with the example for hashing, we have modules under the ```Default``` sub-module, that hides a static instance of the services and providers mentioned,

###### SFX.Crypto.Encryption.Symmetric.Aes.Default.Data

Enables a simpler encryption/decryption example like:

``` fsharp
open SFX.Crypto.Windows.Encryption.Symmetric.Ase.Data
open SFX.Crypto.Windows.Encryption.Symmetric.Aes.Default.Data

let secret = getThatSecret()
let salt = getThatSalt()
do  withAesCryptoServiceProvider() |>
    withSecret secret |>
    withSalt salt |> 
    ignore
....
let payload = computeThatPayload()

match payload |> encrypt with 
| Success encryptedData -> encryptedData |> useTheEncryptedPayloadForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

And similarly for key pair generation we have

###### SFX.Crypto.Encryption.Symmetric.Aes.Default.Key

``` fsharp
open SFX.Crypto.Windows.Encryption.Symmetric.Aes.key
open SFX.Crypto.Windows.Encryption.Symmetric.Aes.Default.key

do withAesCryptoServiceProvider() |> ignore

match generateKeyPair() with 
| Success (secret, salt) -> 
    secret |> useTheSecretForWhatever
    salt |> useTheSaltForWhatever
| Failure error -> error |> tellAboutItTosOleg
```

### Signing

The final module deals with signing data and hashes thereof as well as verifying the generated signatures. For this purpose, we have - again - wrapped the ```SignatureService``` as mentioned earlier. So: 

#### SFX.Crypto.Signature

This module - to the surprise of none - defines a few payload types of the usual kind:

``` fsharp
type Hash = {Value: byte array}
type Payload = {Value: byte array}
type Signature = {Value: byte array}
type SigningKey = {Value: byte array}
type VerificationKey = {Value: byte array}
``` 

where the first two are types, that can be signed (producing a ```Signature```), and later on - on the other end of the wire - verified. Besides that, the following functions have been provided for:

* ```createService: unit -> SignatureService```, creates a ```SignatureService```, that can be used as described above to sign hashes and payloads as well as verifying them.

Before utilizing the service, one needs to:

* Set up the hashing algorithm to utilize.
* Set up the padding mode.
* Set the signing (public) key - must work with ```RSACryptoServiceProvider```.
* Set the verification (private) key - must work with ```RSACryptoServiceProvider```.

To set up the hashing algorithm, one of the following functions ```withSHA1```,  ```withSHA256```, ```withSHA384```, ```withSHA512``` or ```withMD5```, that all have the signature ```SignatureService -> SignatureService```.

To set up padding, invoke one of the following: ```withPkcs1``` or ```withPss```, which again have the signature ```SignatureService -> SignatureService```.

The signing- and verification keys are set up with:
* ```withSigningKey: SigningKey -> SignatureService -> SignatureService``` and
* ```withVerificationKey: VerificationKey -> SignatureService -> SignatureService```

##### SFX.Crypto.Signature.Data

This module contains the two functions to sign and verify ```Payload```s:

* ```sign: Payload -> SignatureService -> Result<Signature, exn>``` and
* ```verify: Payload -> Signature -> SignatureService -> Result<bool, exn>```

##### SFX.Crypto.Signature.Hash

This module contains the two functions to sign and verify ```Hash```es:

* ```sign: Hash -> SignatureService -> Result<Signature, exn>``` and
* ```verify: Hash -> Signature -> SignatureService -> Result<bool, exn>```

##### SFX.Crypto.Signature.Default

Like for all the other services, a module exists, that utilizes a static ```SignatureService``` removing the need to carry around instances thereof. As with hashing and encryption, setup methods with one argument less exist and will not be enumerated here.

##### SFX.Crypto.Signature.Default.Data

This module contains the two functions to sign and verify ```Payload```s:

* ```sign: Payload -> Result<Signature, exn>``` and
* ```verify: Payload -> Signature -> Result<bool, exn>```

##### SFX.Crypto.Signature.Default.Hash

This module contains the two functions to sign and verify ```Hash```es:

* ```sign: Hash -> Result<Signature, exn>``` and
* ```verify: Hash -> Signature -> Result<bool, exn>```

### Oleg?

Who is Oleg in the code mentioned above? Just an abbreviation for the **O**mni **l**oving **e**xception **g**urgler, in case you might favor to use EDCF, that is Exception Driven Control Flow.