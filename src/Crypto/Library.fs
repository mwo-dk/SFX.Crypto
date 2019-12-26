namespace SFX.Crypto
    
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("SFX.Crypto.Windows")>]
do()

open SFX.ROP

module Hashing =
    open SFX.Crypto.CSharp.Infrastructure.Hashing
        
    let createService() = new HashService()
    let withSHA1CryptoServiceProvider (service: HashService) =
        service.WithSHA1CryptoServiceProvider()
    let withSHA1Managed (service: HashService) =
        service.WithSHA1Managed()
    let withSHA256CryptoServiceProvider (service: HashService) =
        service.WithSHA256CryptoServiceProvider()
    let withSHA256Managed (service: HashService) =
        service.WithSHA256Managed()
    let withSHA384CryptoServiceProvider (service: HashService) =
        service.WithSHA384CryptoServiceProvider()
    let withSHA512CryptoServiceProvider (service: HashService) =
        service.WithSHA512CryptoServiceProvider()
    let withSHA512Managed (service: HashService) =
        service.WithSHA512Managed()
    let withMD5CryptoServiceProvider (service: HashService) =
        service.WithMD5CryptoServiceProvider()

    type Payload = {Value: byte array}
    let private toUnhashedPayload x =
        CSharp.Model.Hashing.Payload(x.Value)
    type Hash = {Value: byte array}
    let private fromHash (x: SFX.Crypto.CSharp.Model.Hashing.IHash) : Hash =
        {Value = x.Value}

    let computeHash x (service: HashService) =
        match service.ComputeHash(x |> toUnhashedPayload) |> toResult with
        | Success x -> x |> fromHash |> succeed
        | Failure error -> error |> fail

    module Default =

        let private service = new HashService()
        let withSHA1CryptoServiceProvider() =
            service.WithSHA1CryptoServiceProvider()
        let withSHA1Managed() =
            service.WithSHA1Managed()
        let withSHA256CryptoServiceProvider() =
            service.WithSHA256CryptoServiceProvider()
        let withSHA256Managed() =
            service.WithSHA256Managed()
        let withSHA384CryptoServiceProvider() =
            service.WithSHA384CryptoServiceProvider()
        let withSHA512CryptoServiceProvider() =
            service.WithSHA512CryptoServiceProvider()
        let withSHA512Managed() =
            service.WithSHA512Managed()
        let withMD5CryptoServiceProvider() =
            service.WithMD5CryptoServiceProvider()

        let computeHash x = service |> computeHash x

module Encryption =
    module Asymmetric =
        module RSA =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA

            type EncryptionKey = {Value: byte array}
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
                let createService() = new CryptoService()
                let withRSACryptoServiceProvider (service: CryptoService) =
                    service.WithRSACryptoServiceProvider()
                let withEncryptionKey key (service: CryptoService) =
                    service.WithEncryptionKey(key |> toEncryptionKey)
                let withDecryptionKey key (service: CryptoService) =
                    service.WithDeryptionKey(key |> toDecryptionKey)

                type UnencryptedPayload = {Value: byte array}
                type EncryptedPayload = {Value: byte array}

                let internal toUnencryptedPayload (x: UnencryptedPayload) = 
                    CSharp.Model.Crypto.Asymmetric.RSA.UnencryptedPayload(x.Value)
                let internal fromEncryptedPayload (x: SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.IEncryptedPayload) : EncryptedPayload =
                    {Value = x.Value}
                let internal toEncryptedPayload (x: EncryptedPayload) = 
                    CSharp.Model.Crypto.Asymmetric.RSA.EncryptedPayload(x.Value)
                let internal fromUnencryptedPayload (x: SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.IUnencryptedPayload) : UnencryptedPayload =
                    {Value = x.Value}
            
                let encrypt payload (service: CryptoService) =
                    match service.Encrypt(payload |> toUnencryptedPayload) |> toResult with
                    | Success x -> x |> fromEncryptedPayload |> succeed
                    | Failure error -> error |> fail
                let decrypt payload (service: CryptoService) =
                    match service.Decrypt(payload |> toEncryptedPayload) |> toResult with
                    | Success x -> x |> fromUnencryptedPayload |> succeed
                    | Failure error -> error |> fail

            module Key =
                let createKeyPairProvider = RandomKeyPairProvider
                let withRSACryptoServiceProvider (keyPairProvider: RandomKeyPairProvider) =
                    keyPairProvider.WithRSACryptoServiceProvider()
                let generateKeyPair (keyPairProvider: RandomKeyPairProvider) =
                    match keyPairProvider.GenerateKeyPair() |> toResult with
                    | Success (x, y) ->
                        (x |> fromEncrytionKey, y |> fromDecryptionKey) |> succeed
                    | Failure error -> error |> fail

            module Default =
                module Data =
                    let internal service = new CryptoService()
                    let withRSACryptoServiceProvider() =
                        service.WithRSACryptoServiceProvider()

                    let encrypt payload = service |> Data.encrypt payload
                    let decrypt payload = service |> Data.decrypt payload

                module Key =
                    let internal keyPairProvider = RandomKeyPairProvider()
                    let withRSACryptoServiceProvider() =
                        keyPairProvider.WithRSACryptoServiceProvider()

                    let generateKeyPair() = keyPairProvider |> Key.generateKeyPair

    module Symmetric =
        module Aes =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
            
            type Secret = {Value: byte array}
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
                let createService() = new CryptoService()
                let withAesCryptoServiceProvider (x: CryptoService) =
                    x.WithAesCryptoServiceProvider()
                let withAesManaged (x: CryptoService) =
                    x.WithAesManaged()
                let withSecret secret (x: CryptoService) =
                    x.WithSecret(secret |> toSecret)
                let withSalt salt (x: CryptoService) =
                    x.WithSalt(salt |> toSalt)

                type UnencryptedPayload = {Value: byte array}
                type EncryptedPayload = {Value: byte array}

                let private toUnencryptedPayload (x: UnencryptedPayload) = 
                    CSharp.Model.Crypto.Symmetric.Aes.UnencryptedPayload(x.Value)
                let private fromEncryptedPayload (x: CSharp.Model.Crypto.Symmetric.Aes.IEncryptedPayload) : EncryptedPayload =
                    {Value = x.Value}
                let private toEncryptedPayload (x: EncryptedPayload) = 
                    CSharp.Model.Crypto.Symmetric.Aes.EncryptedPayload(x.Value)
                let private fromUnencryptedPayload (x: CSharp.Model.Crypto.Symmetric.Aes.IUnencryptedPayload) : UnencryptedPayload =
                    {Value = x.Value}

                let encrypt payload (service: CryptoService) =
                    match service.Encrypt(payload |> toUnencryptedPayload) |> toResult with
                    | Success x -> x |> fromEncryptedPayload |> succeed
                    | Failure error -> error |> fail
                let decrypt payload (service: CryptoService) =
                    match service.Decrypt(payload |> toEncryptedPayload) |> toResult with
                    | Success x -> x |> fromUnencryptedPayload |> succeed
                    | Failure error -> error |> fail

            module Key =
                let createKeyPairProvider = RandomSecretAndSaltProvider
                let withAesCryptoServiceProvider (keyPairProvider: RandomSecretAndSaltProvider) =
                    keyPairProvider.WithAesCryptoServiceProvider()
                let withAesManaged (keyPairProvider: RandomSecretAndSaltProvider) =
                    keyPairProvider.WithAesManaged()
                let generateKeyPair (keyPairProvider: RandomSecretAndSaltProvider) =
                    match keyPairProvider.GenerateKeyPair() |> toResult with
                    | Success (x, y) ->
                        (x |> fromSecret, y |> fromSalt) |> succeed
                    | Failure error -> error |> fail

            module Default =

                module Data =
                    let internal service = new CryptoService()
                    let withAesCryptoServiceProvider() =
                        service.WithAesCryptoServiceProvider()
                    let WithAesManaged() =
                        service.WithAesManaged()

                    let encrypt payload = service |> Data.encrypt payload
                    let decrypt payload = service |> Data.decrypt payload

                module Key =
                    let internal keyProvider = RandomSecretAndSaltProvider()

                    let generateKeyPair() = keyProvider |> Key.generateKeyPair

module Signature =
    open SFX.Crypto.CSharp.Infrastructure.Signature
    
    type Hash = {Value: byte array}
    let toHash (x: Hash) =
        CSharp.Model.Signature.Hash(x.Value) :> SFX.Crypto.CSharp.Model.Signature.IHash
    type Payload = {Value: byte array}
    let toPayload (x: Payload) =
        CSharp.Model.Signature.Payload(x.Value) :> SFX.Crypto.CSharp.Model.Signature.IPayload
    type Signature = {Value: byte array}
    let toSignature (x: Signature) =
        CSharp.Model.Signature.Signature(x.Value) :> SFX.Crypto.CSharp.Model.Signature.ISignature
    let fromSignature (x: SFX.Crypto.CSharp.Model.Signature.ISignature) : Signature =
        {Value = x.Value}
    type SigningKey = {Value: byte array}
    let toSigningKey (x: SigningKey) = 
        CSharp.Model.Signature.SigningKey(x.Value) :> SFX.Crypto.CSharp.Model.Signature.ISigningKey
    type VerificationKey = {Value: byte array}
    let toVericationKey (x: VerificationKey) = 
        CSharp.Model.Signature.VerificationKey(x.Value) :> SFX.Crypto.CSharp.Model.Signature.IVerificationKey

    let createService() = new SignatureService()

    let withSHA1 (service: SignatureService) =
        service.WithSHA1()
    let withSHA256 (service: SignatureService) =
        service.WithSHA256()
    let withSHA384 (service: SignatureService) =
        service.WithSHA384()
    let withSHA512 (service: SignatureService) =
        service.WithSHA512()
    let withMD5 (service: SignatureService) =
        service.WithMD5()

    let withPkcs1 (service: SignatureService) =
        service.WithPkcs1()
    let withPss (service: SignatureService) = 
        service.WithPss()

    let withSigningKey (key: SigningKey) (service: SignatureService) =
        service.WithSigningKey(key |> toSigningKey)
    let withVerificationKey (key: VerificationKey) (service: SignatureService) =
        service.WithVerificationKey(key |> toVericationKey)

    module Data =

        let sign (payload: Payload) (service: SignatureService) =
            match service.SignPayload(payload |> toPayload) |> toResult with
            | Success result -> result |> fromSignature |> succeed
            | Failure exn -> exn |> fail
        let verify (payload: Payload) (signature: Signature) (service: SignatureService) =
            service.VerifyPayload(payload |> toPayload, signature |> toSignature) |> toResult

    module Hash =

        let sign (payload: Hash) (service: SignatureService) =
            match service.SignHash(payload |> toHash) |> toResult with
            | Success result -> result |> fromSignature |> succeed
            | Failure exn -> exn |> fail
        let verify (payload: Hash) (signature: Signature) (service: SignatureService) =
            service.VerifyHash(payload |> toHash, signature |> toSignature) |> toResult

    module Default =

        let internal service = new SignatureService()

        let withSHA1() =
            service.WithSHA1()
        let withSHA256() =
            service.WithSHA256()
        let withSHA384() =
            service.WithSHA384()
        let withSHA512() =
            service.WithSHA512()
        let withMD5() =
            service.WithMD5()

        let withPkcs1() =
            service.WithPkcs1()
        let withPss() = 
            service.WithPss()
            
        let withSigningKey (key: SigningKey) =
            service.WithSigningKey(key |> toSigningKey)
        let withVerificationKey (key: VerificationKey) =
            service.WithVerificationKey(key |> toVericationKey)

        module Data =

            let sign (payload: Payload) =
                match service.SignPayload(payload |> toPayload) |> toResult with
                | Success result -> result |> fromSignature |> succeed
                | Failure exn -> exn |> fail
            let verify (payload: Payload) (signature: Signature) =
                service.VerifyPayload(payload |> toPayload, signature |> toSignature) |> toResult

        module Hash =

            let sign (payload: Hash) =
                match service.SignHash(payload |> toHash) |> toResult with
                | Success result -> result |> fromSignature |> succeed
                | Failure exn -> exn |> fail
            let verify (payload: Hash) (signature: Signature) =
                service.VerifyHash(payload |> toHash, signature |> toSignature) |> toResult