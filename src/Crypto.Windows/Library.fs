namespace SFX.Crypto.Windows

open SFX.ROP

module Crypto =
    module Asymmetric =
        module RSA =
            
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA

            let private service = new CryptoService()

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
            let private toDecryptionKey (x: DecryptionKey) = 
                SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA.DecryptionKey(x.Value)
            
            let encrypt payload key =
                match service.Encrypt(payload |> toUnencryptedPayload, key |> toEncryptionKey) |> toResult with
                | Success x -> x |> fromEncryptedPayload |> succeed
                | Failure error -> error |> fail
            
            let decrypt payload key =
                match service.Decrypt(payload |> toEncryptedPayload, key |> toDecryptionKey) |> toResult with
                | Success x -> x |> fromUnencryptedPayload |> succeed
                | Failure error -> error |> fail

    module Symmetric =
        module Aes =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes

            let private service = new CryptoService()
            
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
            let private toSalt (x: Salt) = 
                SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes.Salt(x.Value)
            
            let encrypt payload secret salt =
                match service.Encrypt(payload |> toUnencryptedPayload, secret |> toSecret, salt |> toSalt) |> toResult with
                | Success x -> x |> fromEncryptedPayload |> succeed
                | Failure error -> error |> fail
            
            let decrypt payload secret salt =
                match service.Decrypt(payload |> toEncryptedPayload, secret |> toSecret, salt |> toSalt) |> toResult with
                | Success x -> x |> fromUnencryptedPayload |> succeed
                | Failure error -> error |> fail