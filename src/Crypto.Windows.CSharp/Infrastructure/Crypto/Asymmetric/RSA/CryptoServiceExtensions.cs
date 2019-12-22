﻿using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using System.Security.Cryptography;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    public static class CryptoServiceExtensions
    {
        public static CryptoService WithRSACng(this CryptoService service) =>
            service.WithAlgorihm(new RSACng());

        public static RandomKeyPairProvider WithRSACng(this RandomKeyPairProvider provider)
        {
            RandomKeyPairProviderExtensions
                .WithAlgorithm<RandomKeyPairProvider, EncryptionKey, DecryptionKey>(provider, new RSACng());
            return provider;
        }
    }
}
