using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Rijndael;
using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Rijndael
{
    /// <summary>
    /// Implements <see cref="IRandomSecretAndSaltProvider"/>
    /// </summary>
    public sealed class RandomSecretAndSaltProvider : IRandomSecretAndSaltProvider
    {
        public RandomSecretAndSaltProvider() =>
            Algorithm = new AesCryptoServiceProvider();

        /// <inheritdoc/>
        public Result<(ISecret Secret, ISalt Salt)> GenerateKeyPair()
        {
            if (Algorithm is null)
                return Fail<(ISecret, ISalt)>(new InvalidOperationException("RandomSecretAndSaltProvider is not initialized"));
            try
            {
                Algorithm.GenerateKey();
                Algorithm.GenerateIV();
                var secret = new Secret(Algorithm.Key) as ISecret;
                var salt = new Salt(Algorithm.IV) as ISalt;
                return Succeed((secret, salt));
            }
            catch (Exception error)
            {
                return Fail<(ISecret, ISalt)>(error);
            }
        }

        internal System.Security.Cryptography.Aes Algorithm;
        /// <inheritdoc/>
        public IRandomSecretAndSaltProvider WithAlgorithm(System.Security.Cryptography.Aes algorithm)
        {
            if (!(Algorithm is null))
                Algorithm.Dispose();

            Algorithm = algorithm;
            return this;
        }
    }

    public static class RandomSecretAndSaltProviderExtensions
    {
        /// <summary>
        /// Instruments <paramref name="service"/> to utilize <see cref="AesCryptoServiceProvider"/>
        /// </summary>
        /// <param name="service"></param>
        /// <returns><paramref name="service"/></returns>
        public static IRandomSecretAndSaltProvider WithAesCryptoServiceProvider(this IRandomSecretAndSaltProvider service) =>
            service?.WithAlgorithm(new AesCryptoServiceProvider());
        /// <summary>
        /// Instruments <paramref name="service"/> to utilize <see cref="AesManaged"/>
        /// </summary>
        /// <param name="service"></param>
        /// <returns><paramref name="service"/></returns>
        public static IRandomSecretAndSaltProvider WithAesManaged(this IRandomSecretAndSaltProvider service) =>
            service?.WithAlgorithm(new AesManaged());
    }
}
