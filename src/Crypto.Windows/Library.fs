namespace SFX.Crypto.Windows

module Encryption =
    module Asymmetric =
        module RSA =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA

            module Data =
                let withRSACng (service: CryptoService) =
                    service.WithRSACng()

            module Key =
                let withRSACng (provider: RandomKeyPairProvider) =
                    provider.WithRSACng()

            module Default =
                module Data =
                    let withRSACng() = SFX.Crypto.Encryption.Asymmetric.RSA.Default.Data.service |> Data.withRSACng

                module Key =
                    let withRSACng() = SFX.Crypto.Encryption.Asymmetric.RSA.Default.Key.keyPairProvider |> Key.withRSACng

    module Symmetric =
        module Aes =
            open SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes

            module Data =
                let withAesCng (service: CryptoService) =
                    SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes.CryptoServiceExtensions.WithAesCng(service)

            module Key =
                let withAesCng (provider: RandomSecretAndSaltProvider) =
                    SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes.CryptoServiceExtensions.WithAesCng(provider)

            module Default =

                module Data =
                    let withAesCng() = 
                        SFX.Crypto.Encryption.Symmetric.Aes.Default.Data.service |> Data.withAesCng

                module Key =
                    let withAesCng() = 
                        SFX.Crypto.Encryption.Symmetric.Aes.Default.Key.keyProvider |> Key.withAesCng