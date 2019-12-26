using System.Security.Cryptography;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    public static class CryptoServiceExtensions
    {
        public static CryptoService WithAesCng(this CryptoService service) =>
            service.WithAlgorihm(new AesCng());

        public static RandomSecretAndSaltProvider WithAesCng(this RandomSecretAndSaltProvider provider) =>
            provider.WithAlgorithm(new AesCng());
    }
}
