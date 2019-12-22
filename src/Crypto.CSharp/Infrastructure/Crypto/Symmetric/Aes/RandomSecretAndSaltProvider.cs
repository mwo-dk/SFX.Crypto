using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes;
using SFX.ROP.CSharp;
using System;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Implements <see cref="IRandomSecretAndSaltProvider"/>
    /// </summary>
    public sealed class RandomSecretAndSaltProvider : IRandomSecretAndSaltProvider
    {
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

        internal RandomSecretAndSaltProvider WithAlgorithm(System.Security.Cryptography.Aes algorithm)
        {
            Algorithm = algorithm;
            return this;
        }
        public RandomSecretAndSaltProvider WithAesCryptoServiceProvider() =>
            WithAlgorithm(new System.Security.Cryptography.AesCryptoServiceProvider());

        public RandomSecretAndSaltProvider WithAesManaged() =>
            WithAlgorithm(new System.Security.Cryptography.AesManaged());
    }
}
