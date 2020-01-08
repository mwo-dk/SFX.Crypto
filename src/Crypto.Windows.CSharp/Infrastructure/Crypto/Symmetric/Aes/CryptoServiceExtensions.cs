using System.Security.Cryptography;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    public static class CryptoServiceExtensions
    {
        /// <summary>
        /// Instruments <paramref name="service"/> to utilize <see cref="AesCng"/>
        /// </summary>
        /// <param name="service"></param>
        /// <returns><paramref name="service"/></returns>
        public static ICryptoService WithAesCng(this ICryptoService service) =>
            service?.WithAlgorihm(new AesCng());

        /// <summary>
        /// Instruments <paramref name="provider"/> to utilize <see cref="AesCng"/>
        /// </summary>
        /// <param name="provider"></param>
        /// <returns><paramref name="service"/></returns>
        public static IRandomSecretAndSaltProvider WithAesCng(this IRandomSecretAndSaltProvider provider) =>
            provider?.WithAlgorithm(new AesCng());
    }
}
