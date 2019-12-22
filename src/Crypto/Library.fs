namespace SFX.Crypto

open SFX.ROP

module Crypto =
    module Asymmetric =
        module RSA =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA

            let private service = new CryptoService()
            let createService() = new CryptoService()
            let withRSACryptoServiceProvider (x: CryptoService) =
                x.WithRSACryptoServiceProvider()

            type UnencryptedPayload = {Value: byte array}
            type EncryptedPayload = {Value: byte array}
            type EncryptionKey = {Value: byte array}
            type DecryptionKey = {Value: byte array}

            let private toUnencryptedPayload (x: UnencryptedPayload) = 
                SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.UnencryptedPayload(x.Value)
            let private fromEncryptedPayload (x: SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.IEncryptedPayload) : EncryptedPayload =
                {Value = x.Value}
            let private toEncryptedPayload (x: EncryptedPayload) = 
                SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.EncryptedPayload(x.Value)
            let private fromUnencryptedPayload (x: SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.IUnencryptedPayload) : UnencryptedPayload =
                {Value = x.Value}
            
            let private toEncryptionKey (x: EncryptionKey) = 
                SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.EncryptionKey(x.Value)
            let private fromEncrytionKey (x: SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.IEncryptionKey) : EncryptionKey =
                {Value = x.Value}
            let private toDecryptionKey (x: DecryptionKey) = 
                SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.DecryptionKey(x.Value)
            let private fromDecryptionKey (x: SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.IDecryptionKey) : DecryptionKey =
                {Value = x.Value}
            
            let encrypt payload key =
                match service.Encrypt(payload |> toUnencryptedPayload, key |> toEncryptionKey) |> toResult with
                | Success x -> x |> fromEncryptedPayload |> succeed
                | Failure error -> error |> fail
            
            let decrypt payload key =
                match service.Decrypt(payload |> toEncryptedPayload, key |> toDecryptionKey) |> toResult with
                | Success x -> x |> fromUnencryptedPayload |> succeed
                | Failure error -> error |> fail

            let private keyprovider = RandomKeyPairProvider()
            let generateKeyPair() =
                match keyprovider.GenerateKeyPair() |> toResult with
                | Success (x, y) ->
                    (x |> fromEncrytionKey, y |> fromDecryptionKey) |> succeed
                | Failure error -> error |> fail

    module Symmetric =
        module Aes =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
            
            let private service = new CryptoService()
            let createService() = new CryptoService()
            let withAesCryptoServiceProvider (x: CryptoService) =
                x.WithAesCryptoServiceProvider()
            let withAesManaged (x: CryptoService) =
                x.WithAesManaged()
            
            type UnencryptedPayload = {Value: byte array}
            type EncryptedPayload = {Value: byte array}
            type Secret = {Value: byte array}
            type Salt = {Value: byte array}
            
            let private toUnencryptedPayload (x: UnencryptedPayload) = 
                SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes.UnencryptedPayload(x.Value)
            let private fromEncryptedPayload (x: SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes.IEncryptedPayload) : EncryptedPayload =
                {Value = x.Value}
            let private toEncryptedPayload (x: EncryptedPayload) = 
                SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes.EncryptedPayload(x.Value)
            let private fromUnencryptedPayload (x: SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes.IUnencryptedPayload) : UnencryptedPayload =
                {Value = x.Value}
            
            let private toSecret (x: Secret) = 
                SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes.Secret(x.Value)
            let private fromSecret (x: SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes.ISecret) : Secret =
                {Value = x.Value}
            let private toSalt (x: Salt) = 
                SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes.Salt(x.Value)
            let private fromSalt (x: SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes.ISalt) : Salt =
                {Value = x.Value}
            let encrypt payload secret salt =
                match service.Encrypt(payload |> toUnencryptedPayload, secret |> toSecret, salt |> toSalt) |> toResult with
                | Success x -> x |> fromEncryptedPayload |> succeed
                | Failure error -> error |> fail
            
            let decrypt payload secret salt =
                match service.Decrypt(payload |> toEncryptedPayload, secret |> toSecret, salt |> toSalt) |> toResult with
                | Success x -> x |> fromUnencryptedPayload |> succeed
                | Failure error -> error |> fail

            let private keyprovider = RandomSecretAndSaltProvider()
            let generateKeyPair() =
                match keyprovider.GenerateKeyPair() |> toResult with
                | Success (x, y) ->
                    (x |> fromSecret, y |> fromSalt) |> succeed
                | Failure error -> error |> fail

module Hash =
    module SHA512 =
        open SFX.Crypto.CSharp.Infrastructure.Hashing
        
        let private service = new HashService()

        type Payload = {Value: byte array}
        type Hash = {Value: byte array}
        let toUnhashedPayload x =
            SFX.Crypto.CSharp.Model.Hashing.Payload(x.Value)
        let fromHash (x: SFX.Crypto.CSharp.Model.Hashing.IHash) : Hash =
            {Value = x.Value}

        let computeHash x =
            match service.ComputeHash(x |> toUnhashedPayload) |> toResult with
            | Success x -> x |> fromHash |> succeed
            | Failure error -> error |> fail

module Signature =
    open SFX.Crypto.CSharp.Infrastructure.Signature

    let private service = SignatureService()
    let createSignatureService = SignatureService

    type Hash = {Value: byte array}
    type Payload = {Value: byte array}
    type Signature = {Value: byte array}
    type SigningKey = {Value: byte array}
    type VerificationKey = {Value: byte array}

    let toHash (x: Hash) =
        SFX.Crypto.CSharp.Model.Signature.Hash(x.Value) :> SFX.Crypto.CSharp.Model.Signature.IHash
    let toPayload (x: Payload) =
        SFX.Crypto.CSharp.Model.Signature.Payload(x.Value) :> SFX.Crypto.CSharp.Model.Signature.IPayload
    let toSignature (x: Signature) =
        SFX.Crypto.CSharp.Model.Signature.Signature(x.Value) :> SFX.Crypto.CSharp.Model.Signature.ISignature
    let fromSignature (x: SFX.Crypto.CSharp.Model.Signature.ISignature) : Signature =
        {Value = x.Value}
    let toSigningKey (x: SigningKey) = 
        SFX.Crypto.CSharp.Model.Signature.SigningKey(x.Value) :> SFX.Crypto.CSharp.Model.Signature.ISigningKey
    let toVericationKey (x: VerificationKey) = 
        SFX.Crypto.CSharp.Model.Signature.VerificationKey(x.Value) :> SFX.Crypto.CSharp.Model.Signature.IVerificationKey

    type Service =
    | Default
    | S of SignatureService
    let getService x =
        match x with
        | Default -> service
        | S svc -> svc

    let withDefault() = Default
    let withService() = createSignatureService() |> S

    type Param =
    | S of Service*SigningKey
    | V of Service*VerificationKey
    | SV of Service*SigningKey*VerificationKey

    let withSigningKey key x =
        match x with
        | S (s,_) -> S (s, key)
        | V (s, k) -> SV (s, key, k)
        | SV (s, _, k) -> SV(s, key, k)

    let withVerificationKey key x =
        match x with
        | S (s,k) -> SV (s, k, key)
        | V (s, _) -> V (s, key)
        | SV (s, k, _) -> SV(s, k, key)

    type SignArg =
    | P of Payload
    | H of Hash

    let sign x p =
        let svc =
            match p with
            | S (s, k) -> (s |> getService).WithSigningKey(k |> toSigningKey)
            | V (s, k) -> (s |> getService).WithVerificationKey(k |> toVericationKey)
            | SV (s, sk, vk) -> 
                (s |> getService).WithSigningKey(sk |> toSigningKey).WithVerificationKey(vk |> toVericationKey)
        match x with
        | P x -> 
            match svc.SignPayload(x |> toPayload) |> toResult with
            | Success x -> x |> fromSignature |> succeed
            | Failure error -> error |> fail
        | H x ->
            match svc.SignHash(x |> toHash) |> toResult with
            | Success x -> x |> fromSignature |> succeed
            | Failure error -> error |> fail
    
    let verify x s p =
        let svc =
            match p with
            | S (s, k) -> (s |> getService).WithSigningKey(k |> toSigningKey)
            | V (s, k) -> (s |> getService).WithVerificationKey(k |> toVericationKey)
            | SV (s, sk, vk) -> 
                (s |> getService).WithSigningKey(sk |> toSigningKey).WithVerificationKey(vk |> toVericationKey)
        match x with
        | P x -> 
            match svc.VerifyPayload(x |> toPayload, s |> toSignature) |> toResult with
            | Success x -> x |> succeed
            | Failure error -> error |> fail
        | H x ->
            match svc.VerifyHash(x |> toHash, s |> toSignature) |> toResult with
            | Success x -> x |> succeed
            | Failure error -> error |> fail