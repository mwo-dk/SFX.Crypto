namespace SFX.Crypto
    
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("SFX.Crypto.Windows")>]
do()

open SFX.ROP

module Hashing =
    open SFX.Crypto.CSharp.Infrastructure.Hashing
        
    /// Creates a HashService
    let createService() = new HashService()
    /// Instruments the HashService to utilize SHA1 (SHA1CryptoServiceProvider)
    let withSHA1CryptoServiceProvider (service: HashService) =
        service.WithSHA1CryptoServiceProvider()
    /// Instruments the HashService to utilize SHA1 (SHA1Managed)
    let withSHA1Managed (service: HashService) =
        service.WithSHA1Managed()
    /// Instruments the HashService to utilize SHA256 (SHA256CryptoServiceProvider)
    let withSHA256CryptoServiceProvider (service: HashService) =
        service.WithSHA256CryptoServiceProvider()
    /// Instruments the HashService to utilize SHA256 (SHA256Managed)
    let withSHA256Managed (service: HashService) =
        service.WithSHA256Managed()
    /// Instruments the HashService to utilize SHA384 (SHA384CryptoServiceProvider)
    let withSHA384CryptoServiceProvider (service: HashService) =
        service.WithSHA384CryptoServiceProvider()
    /// Instruments the HashService to utilize SHA384 (SHA384Managed)
    let withSHA384Managed (service: HashService) =
        service.WithSHA384Managed()
    /// Instruments the HashService to utilize SHA512 (SHA512CryptoServiceProvider)
    let withSHA512CryptoServiceProvider (service: HashService) =
        service.WithSHA512CryptoServiceProvider()
    /// Instruments the HashService to utilize SHA512 (SHA512Managed)
    let withSHA512Managed (service: HashService) =
        service.WithSHA512Managed()
    /// Instruments the HashService to utilize MD5 (MD5CryptoServiceProvider)
    let withMD5CryptoServiceProvider (service: HashService) =
        service.WithMD5CryptoServiceProvider()

    /// Represents a payload to be hashed
    type Payload = {Value: byte array}
    let private toUnhashedPayload x =
        CSharp.Model.Hashing.Payload(x.Value)
    /// Represents a hashed payload
    type Hash = {Value: byte array}
    let private fromHash (x: SFX.Crypto.CSharp.Model.Hashing.IHash) : Hash =
        {Value = x.Value}

    /// Computes the hash of the provided payload
    let computeHash x (service: HashService) =
        match service.ComputeHash(x |> toUnhashedPayload) |> toResult with
        | Success x -> x |> fromHash |> succeed
        | Failure error -> error |> fail

    module Default =

        let private service = new HashService()
        /// Instruments the HashService to utilize SHA1 (SHA1CryptoServiceProvider)
        let withSHA1CryptoServiceProvider() =
            service.WithSHA1CryptoServiceProvider()
        /// Instruments the HashService to utilize SHA1 (SHA1Managed)
        let withSHA1Managed() =
            service.WithSHA1Managed()
        /// Instruments the HashService to utilize SHA256 (SHA256CryptoServiceProvider)
        let withSHA256CryptoServiceProvider() =
            service.WithSHA256CryptoServiceProvider()
        /// Instruments the HashService to utilize SHA256 (SHA256Managed)
        let withSHA256Managed() =
            service.WithSHA256Managed()
        /// Instruments the HashService to utilize SHA384 (SHA384CryptoServiceProvider)
        let withSHA384CryptoServiceProvider() =
            service.WithSHA384CryptoServiceProvider()
        /// Instruments the HashService to utilize SHA384 (SHA384Managed)
        let withSHA384Managed() =
            service.WithSHA384Managed()
        /// Instruments the HashService to utilize SHA512 (SHA512CryptoServiceProvider)
        let withSHA512CryptoServiceProvider() =
            service.WithSHA512CryptoServiceProvider()
        /// Instruments the HashService to utilize SHA512 (SHA512Managed)
        let withSHA512Managed() =
            service.WithSHA512Managed()
        /// Instruments the HashService to utilize MD5 (MD5CryptoServiceProvider)
        let withMD5CryptoServiceProvider() =
            service.WithMD5CryptoServiceProvider()

        let computeHash x = service |> computeHash x

module Encryption =
    module Asymmetric =
        module RSA =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA

            /// Represents an encryption (public) key for RSA encryption
            type EncryptionKey = {Value: byte array}
            /// Represents a decryption (private) key for RSA encryption
            type DecryptionKey = {Value: byte array}

            let private toEncryptionKey (x: EncryptionKey) =
                CSharp.Model.Crypto.Asymmetric.RSA.EncryptionKey(x.Value)
            let private fromEncrytionKey (x: CSharp.Model.Crypto.Asymmetric.RSA.IEncryptionKey) : EncryptionKey =
                {Value = x.Value}
            let private toDecryptionKey (x: DecryptionKey) =
                CSharp.Model.Crypto.Asymmetric.RSA.DecryptionKey(x.Value)
            let private fromDecryptionKey (x: CSharp.Model.Crypto.Asymmetric.RSA.IDecryptionKey) : DecryptionKey =
                {Value = x.Value}

            module Data =
                /// Creates a CryptoService
                let createService() = new CryptoService()
                /// Instruments the CryptoService to utilize RSACryptoServiceProvider
                let withRSACryptoServiceProvider (service: CryptoService) =
                    service.WithRSACryptoServiceProvider()
                /// Instruments the CryptoService to utilize the provided encryption key
                let withEncryptionKey key (service: CryptoService) =
                    service.WithEncryptionKey(key |> toEncryptionKey)
                /// Instruments the CryptoService to utilize the provided decryption key
                let withDecryptionKey key (service: CryptoService) =
                    service.WithDeryptionKey(key |> toDecryptionKey)

                /// Represents an unencrypted payload
                type UnencryptedPayload = {Value: byte array}
                /// Represents an encrypted payload
                type EncryptedPayload = {Value: byte array}

                let internal toUnencryptedPayload (x: UnencryptedPayload) = 
                    CSharp.Model.Crypto.Asymmetric.RSA.UnencryptedPayload(x.Value)
                let internal fromEncryptedPayload (x: SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.IEncryptedPayload) : EncryptedPayload =
                    {Value = x.Value}
                let internal toEncryptedPayload (x: EncryptedPayload) = 
                    CSharp.Model.Crypto.Asymmetric.RSA.EncryptedPayload(x.Value)
                let internal fromUnencryptedPayload (x: SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.IUnencryptedPayload) : UnencryptedPayload =
                    {Value = x.Value}
            
                /// Encrypts the provided payload
                let encrypt payload (service: CryptoService) =
                    match service.Encrypt(payload |> toUnencryptedPayload) |> toResult with
                    | Success x -> x |> fromEncryptedPayload |> succeed
                    | Failure error -> error |> fail
                /// Decrypts the provided payload
                let decrypt payload (service: CryptoService) =
                    match service.Decrypt(payload |> toEncryptedPayload) |> toResult with
                    | Success x -> x |> fromUnencryptedPayload |> succeed
                    | Failure error -> error |> fail

            module Key =
                /// Creates a RandomKeyPairProvider
                let createKeyPairProvider = RandomKeyPairProvider
                
                /// Instruments the RandomKeyPairProvider to utilize RSACryptoServiceProvider
                let withRSACryptoServiceProvider (keyPairProvider: RandomKeyPairProvider) =
                    keyPairProvider.WithRSACryptoServiceProvider()
                /// Generates a key pair
                let generateKeyPair (keyPairProvider: RandomKeyPairProvider) =
                    match keyPairProvider.GenerateKeyPair() |> toResult with
                    | Success (x, y) ->
                        (x |> fromEncrytionKey, y |> fromDecryptionKey) |> succeed
                    | Failure error -> error |> fail

            module Default =
                module Data =
                    let internal service = new CryptoService()
                    /// Instruments the CryptoService to utilize RSACryptoServiceProvider
                    let withRSACryptoServiceProvider() =
                        service.WithRSACryptoServiceProvider()

                    /// Encrypts the provided payload
                    let encrypt payload = service |> Data.encrypt payload
                    /// Decrypts the provided payload
                    let decrypt payload = service |> Data.decrypt payload

                module Key =
                    let internal keyPairProvider = RandomKeyPairProvider()
                    /// Instruments the RandomKeyPairProvider to utilize RSACryptoServiceProvider
                    let withRSACryptoServiceProvider() =
                        keyPairProvider.WithRSACryptoServiceProvider()

                    /// Generates a key pair
                    let generateKeyPair() = keyPairProvider |> Key.generateKeyPair

    module Symmetric =
        module Aes =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
            
            /// Represents the secret to utilize in Aes encryption
            type Secret = {Value: byte array}
            /// Represents the salt to utilize in Aes encryption
            type Salt = {Value: byte array}
            
            let private toSecret (x: Secret) =
                CSharp.Model.Crypto.Symmetric.Aes.Secret(x.Value)
            let private fromSecret (x: CSharp.Model.Crypto.Symmetric.Aes.ISecret) : Secret =
                {Value = x.Value}
            let private toSalt (x: Salt) =
                CSharp.Model.Crypto.Symmetric.Aes.Salt(x.Value)
            let private fromSalt (x: CSharp.Model.Crypto.Symmetric.Aes.ISalt) : Salt =
                {Value = x.Value}
            
            module Data =
                /// Creates a CryptoService
                let createService() = new CryptoService()
                /// Instruments the CryptoService to utilize AesCryptoServiceProvider
                let withAesCryptoServiceProvider (x: CryptoService) =
                    x.WithAesCryptoServiceProvider()
                /// Instruments the CryptoService to utilize AesManaged
                let withAesManaged (x: CryptoService) =
                    x.WithAesManaged()
                /// Instruments the CryptoService to utilize the provided secret
                let withSecret secret (x: CryptoService) =
                    x.WithSecret(secret |> toSecret)
                /// Instruments the CryptoService to utilize the provided secret
                let withSalt salt (x: CryptoService) =
                    x.WithSalt(salt |> toSalt)

                /// Represents an unencrypted payload
                type UnencryptedPayload = {Value: byte array}
                /// Represents an encrypted payload
                type EncryptedPayload = {Value: byte array}

                let private toUnencryptedPayload (x: UnencryptedPayload) = 
                    CSharp.Model.Crypto.Symmetric.Aes.UnencryptedPayload(x.Value)
                let private fromEncryptedPayload (x: CSharp.Model.Crypto.Symmetric.Aes.IEncryptedPayload) : EncryptedPayload =
                    {Value = x.Value}
                let private toEncryptedPayload (x: EncryptedPayload) = 
                    CSharp.Model.Crypto.Symmetric.Aes.EncryptedPayload(x.Value)
                let private fromUnencryptedPayload (x: CSharp.Model.Crypto.Symmetric.Aes.IUnencryptedPayload) : UnencryptedPayload =
                    {Value = x.Value}

                /// Encrypts the provided payload
                let encrypt payload (service: CryptoService) =
                    match service.Encrypt(payload |> toUnencryptedPayload) |> toResult with
                    | Success x -> x |> fromEncryptedPayload |> succeed
                    | Failure error -> error |> fail
                /// Decrypts the provided payload
                let decrypt payload (service: CryptoService) =
                    match service.Decrypt(payload |> toEncryptedPayload) |> toResult with
                    | Success x -> x |> fromUnencryptedPayload |> succeed
                    | Failure error -> error |> fail

            module Key =
                /// Creates a RandomSecretAndSaltProvider
                let createKeyPairProvider = RandomSecretAndSaltProvider
                /// Instruments the RandomSecretAndSaltProvider to utilize AesCryptoServiceProvider
                let withAesCryptoServiceProvider (keyPairProvider: RandomSecretAndSaltProvider) =
                    keyPairProvider.WithAesCryptoServiceProvider()
                /// Instruments the RandomSecretAndSaltProvider to utilize AesManaged
                let withAesManaged (keyPairProvider: RandomSecretAndSaltProvider) =
                    keyPairProvider.WithAesManaged()
                /// Creates a key pair
                let generateKeyPair (keyPairProvider: RandomSecretAndSaltProvider) =
                    match keyPairProvider.GenerateKeyPair() |> toResult with
                    | Success (x, y) ->
                        (x |> fromSecret, y |> fromSalt) |> succeed
                    | Failure error -> error |> fail

            module Default =

                module Data =
                    let internal service = new CryptoService()
                    /// Instruments the CryptoService to utilize AesCryptoServiceProvider
                    let withAesCryptoServiceProvider() =
                        service.WithAesCryptoServiceProvider()
                    /// Instruments the CryptoService to utilize AesManaged
                    let WithAesManaged() =
                        service.WithAesManaged()

                    /// Encrypts the provided payload
                    let encrypt payload = service |> Data.encrypt payload
                    /// Decrypts the provided payload
                    let decrypt payload = service |> Data.decrypt payload

                module Key =
                    let internal keyProvider = RandomSecretAndSaltProvider()

                    /// Generates a key pair
                    let generateKeyPair() = keyProvider |> Key.generateKeyPair

        module Rijndael =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Rijndael
            
            /// Represents the secret to utilize in Rijndael encryption
            type Secret = {Value: byte array}
            /// Represents the salt to utilize in Rijndael encryption
            type Salt = {Value: byte array}
            
            let private toSecret (x: Secret) =
                CSharp.Model.Crypto.Symmetric.Rijndael.Secret(x.Value)
            let private fromSecret (x: CSharp.Model.Crypto.Symmetric.Rijndael.ISecret) : Secret =
                {Value = x.Value}
            let private toSalt (x: Salt) =
                CSharp.Model.Crypto.Symmetric.Rijndael.Salt(x.Value)
            let private fromSalt (x: CSharp.Model.Crypto.Symmetric.Rijndael.ISalt) : Salt =
                {Value = x.Value}
            
            module Data =
                /// Creates a CryptoService
                let createService() = new CryptoService()
                /// Instruments the CryptoService to utilize RijndaelManaged
                let withRijndaelManaged (x: CryptoService) =
                    x.WithRijndaelManaged()
                /// Instruments the CryptoService to utilize the provided secret
                let withSecret secret (x: CryptoService) =
                    x.WithSecret(secret |> toSecret)
                /// Instruments the CryptoService to utilize the provided secret
                let withSalt salt (x: CryptoService) =
                    x.WithSalt(salt |> toSalt)

                /// Represents an unencrypted payload
                type UnencryptedPayload = {Value: byte array}
                /// Represents an encrypted payload
                type EncryptedPayload = {Value: byte array}

                let private toUnencryptedPayload (x: UnencryptedPayload) = 
                    CSharp.Model.Crypto.Symmetric.Rijndael.UnencryptedPayload(x.Value)
                let private fromEncryptedPayload (x: CSharp.Model.Crypto.Symmetric.Rijndael.IEncryptedPayload) : EncryptedPayload =
                    {Value = x.Value}
                let private toEncryptedPayload (x: EncryptedPayload) = 
                    CSharp.Model.Crypto.Symmetric.Rijndael.EncryptedPayload(x.Value)
                let private fromUnencryptedPayload (x: CSharp.Model.Crypto.Symmetric.Rijndael.IUnencryptedPayload) : UnencryptedPayload =
                    {Value = x.Value}

                /// Encrypts the provided payload
                let encrypt payload (service: CryptoService) =
                    match service.Encrypt(payload |> toUnencryptedPayload) |> toResult with
                    | Success x -> x |> fromEncryptedPayload |> succeed
                    | Failure error -> error |> fail
                /// Decrypts the provided payload
                let decrypt payload (service: CryptoService) =
                    match service.Decrypt(payload |> toEncryptedPayload) |> toResult with
                    | Success x -> x |> fromUnencryptedPayload |> succeed
                    | Failure error -> error |> fail

            module Key =
                /// Creates a RandomSecretAndSaltProvider
                let createKeyPairProvider = RandomSecretAndSaltProvider
                /// Instruments the RandomSecretAndSaltProvider to utilize RijndaelManaged
                let withRijndaelManaged (keyPairProvider: RandomSecretAndSaltProvider) =
                    keyPairProvider.WithRijndaelManaged()
                /// Creates a key pair
                let generateKeyPair (keyPairProvider: RandomSecretAndSaltProvider) =
                    match keyPairProvider.GenerateKeyPair() |> toResult with
                    | Success (x, y) ->
                        (x |> fromSecret, y |> fromSalt) |> succeed
                    | Failure error -> error |> fail

            module Default =

                module Data =
                    let internal service = new CryptoService()
                    /// Instruments the CryptoService to utilize RijndaelCryptoServiceProvider
                    let WithRijndaelManaged() =
                        service.WithRijndaelManaged()

                    /// Encrypts the provided payload
                    let encrypt payload = service |> Data.encrypt payload
                    /// Decrypts the provided payload
                    let decrypt payload = service |> Data.decrypt payload

                module Key =
                    let internal keyProvider = RandomSecretAndSaltProvider()

                    /// Generates a key pair
                    let generateKeyPair() = keyProvider |> Key.generateKeyPair

module Signature =
    open SFX.Crypto.CSharp.Infrastructure.Signature
    
    /// Represents a hash to sign
    type Hash = {Value: byte array}
    let private toHash (x: Hash) =
        CSharp.Model.Signature.Hash(x.Value) :> SFX.Crypto.CSharp.Model.Signature.IHash
    /// Represents a payload to sign
    type Payload = {Value: byte array}
    let private toPayload (x: Payload) =
        CSharp.Model.Signature.Payload(x.Value) :> SFX.Crypto.CSharp.Model.Signature.IPayload
    /// Represents a signature
    type Signature = {Value: byte array}
    let private toSignature (x: Signature) =
        CSharp.Model.Signature.Signature(x.Value) :> SFX.Crypto.CSharp.Model.Signature.ISignature
    let private fromSignature (x: SFX.Crypto.CSharp.Model.Signature.ISignature) : Signature =
        {Value = x.Value}
    /// Represents a signing key
    type SigningKey = {Value: byte array}
    let private toSigningKey (x: SigningKey) = 
        CSharp.Model.Signature.SigningKey(x.Value) :> SFX.Crypto.CSharp.Model.Signature.ISigningKey
    /// Represents a verification key
    type VerificationKey = {Value: byte array}
    let private toVericationKey (x: VerificationKey) = 
        CSharp.Model.Signature.VerificationKey(x.Value) :> SFX.Crypto.CSharp.Model.Signature.IVerificationKey

    /// Creates a signature service
    let createService() = new SignatureService()

    
    /// Instruments the SignatureService to utilize SHA1
    let withSHA1 (service: SignatureService) =
        service.WithSHA1()
    /// Instruments the SignatureService to utilize SHA256
    let withSHA256 (service: SignatureService) =
        service.WithSHA256()
    /// Instruments the SignatureService to utilize SHA384
    let withSHA384 (service: SignatureService) =
        service.WithSHA384()
    /// Instruments the SignatureService to utilize SHA512
    let withSHA512 (service: SignatureService) =
        service.WithSHA512()
    /// Instruments the SignatureService to utilize MD5
    let withMD5 (service: SignatureService) =
        service.WithMD5()

    /// Instruments the SignatureService to utilize PKCS1
    let withPkcs1 (service: SignatureService) =
        service.WithPkcs1()
    /// Instruments the SignatureService to utilize PSS
    let withPss (service: SignatureService) = 
        service.WithPss()

    /// Instruments the SignatureService to utilize the provided signing key
    let withSigningKey (key: SigningKey) (service: SignatureService) =
        service.WithSigningKey(key |> toSigningKey)
    /// Instruments the SignatureService to utilize the provided verification key
    let withVerificationKey (key: VerificationKey) (service: SignatureService) =
        service.WithVerificationKey(key |> toVericationKey)

    module Data =

        /// Signs the provided payload
        let sign (payload: Payload) (service: SignatureService) =
            match service.SignPayload(payload |> toPayload) |> toResult with
            | Success result -> result |> fromSignature |> succeed
            | Failure exn -> exn |> fail
        /// Verifies the provided payload
        let verify (payload: Payload) (signature: Signature) (service: SignatureService) =
            service.VerifyPayload(payload |> toPayload, signature |> toSignature) |> toResult

    module Hash =

        /// Signs the provded hash
        let sign (payload: Hash) (service: SignatureService) =
            match service.SignHash(payload |> toHash) |> toResult with
            | Success result -> result |> fromSignature |> succeed
            | Failure exn -> exn |> fail
        /// Verifies the provided hash
        let verify (payload: Hash) (signature: Signature) (service: SignatureService) =
            service.VerifyHash(payload |> toHash, signature |> toSignature) |> toResult

    module Default =

        let internal service = new SignatureService()

        /// Instruments the SignatureService to utilize SHA1
        let withSHA1() =
            service.WithSHA1()
        /// Instruments the SignatureService to utilize SHA256
        let withSHA256() =
            service.WithSHA256()
        /// Instruments the SignatureService to utilize SHA384
        let withSHA384() =
            service.WithSHA384()
        /// Instruments the SignatureService to utilize SHA512
        let withSHA512() =
            service.WithSHA512()
        /// Instruments the SignatureService to utilize MD5
        let withMD5() =
            service.WithMD5()

        /// Instruments the SignatureService to utilize PKCS1
        let withPkcs1() =
            service.WithPkcs1()
        /// Instruments the SignatureService to utilize PSS
        let withPss() = 
            service.WithPss()
            
        /// Instruments the SignatureService to utilize the provided signing key
        let withSigningKey (key: SigningKey) =
            service.WithSigningKey(key |> toSigningKey)
        /// Instruments the SignatureService to utilize the provided verification key
        let withVerificationKey (key: VerificationKey) =
            service.WithVerificationKey(key |> toVericationKey)

        module Data =

            /// Signs the provided payload
            let sign (payload: Payload) =
                match service.SignPayload(payload |> toPayload) |> toResult with
                | Success result -> result |> fromSignature |> succeed
                | Failure exn -> exn |> fail
            /// Verfies the provided payload
            let verify (payload: Payload) (signature: Signature) =
                service.VerifyPayload(payload |> toPayload, signature |> toSignature) |> toResult

        module Hash =

            /// Signs the provided hash
            let sign (payload: Hash) =
                match service.SignHash(payload |> toHash) |> toResult with
                | Success result -> result |> fromSignature |> succeed
                | Failure exn -> exn |> fail
            /// Verfies the provided hash
            let verify (payload: Hash) (signature: Signature) =
                service.VerifyHash(payload |> toHash, signature |> toSignature) |> toResult