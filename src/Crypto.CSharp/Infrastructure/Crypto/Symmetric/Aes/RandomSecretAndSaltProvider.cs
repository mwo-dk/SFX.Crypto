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
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithmProvider">The <see cref="IAesProvider"/></param>
        public RandomSecretAndSaltProvider(IAesProvider algorithmProvider) =>
            AlgorithmProvider = algorithmProvider ?? throw new ArgumentNullException(nameof(algorithmProvider));

        internal IAesProvider AlgorithmProvider { get; }

        /// <inheritdoc/>
        public Result<(ISecret Secret, ISalt Salt)> GenerateKeyPair()
        {
            System.Security.Cryptography.Aes algorithm = default;
            try
            {
                var success = false;
                Exception error = default;
                (success, error, algorithm) = AlgorithmProvider.GetAlgorithm();
                if (!success)
                    return Fail<(ISecret, ISalt)>(error);
                algorithm.GenerateKey();
                algorithm.GenerateIV();
                var secret = new Secret(algorithm.Key) as ISecret;
                var salt = new Salt(algorithm.IV) as ISalt;
                return Succeed((secret, salt));
            }
            catch (Exception error)
            {
                return Fail<(ISecret, ISalt)>(error);
            }
            finally
            {
                algorithm?.Dispose();
            }
        }
    }
}
