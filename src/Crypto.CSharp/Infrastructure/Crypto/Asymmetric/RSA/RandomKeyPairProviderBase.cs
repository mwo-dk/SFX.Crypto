using SFX.ROP.CSharp;
using System;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Base implementation <see cref="IRandomKeyPairProvider{PUBLICKEY, PRIVATEKEY}"/>
    /// </summary>
    /// <typeparam name="PUBLICKEY">The <see cref="Type"/> of the public key</typeparam>
    /// <typeparam name="PRIVATEKEY">The <see cref="Type"/> of the private key</typeparam>
    public class RandomKeyPairProviderBase<PUBLICKEY, PRIVATEKEY> :
        IRandomKeyPairProvider<PUBLICKEY, PRIVATEKEY>
    {
        private RandomKeyPairProviderBase() { }

        protected RandomKeyPairProviderBase(IRSAProvider algorithmProvider,
            Func<byte[], PUBLICKEY> publicKeyCtor,
            Func<byte[], PRIVATEKEY> privateKeyCtor)
        {
            AlgorithmProvider = algorithmProvider ?? throw new ArgumentNullException(nameof(algorithmProvider));
            PublicKeyCtor = publicKeyCtor ?? throw new ArgumentNullException(nameof(publicKeyCtor));
            PrivateKeyCtor = privateKeyCtor ?? throw new ArgumentNullException(nameof(privateKeyCtor));
        }

        internal IRSAProvider AlgorithmProvider { get; }
        internal Func<byte[], PUBLICKEY> PublicKeyCtor { get; }
        internal Func<byte[], PRIVATEKEY> PrivateKeyCtor { get; }

        /// <inheritdoc/>
        public Result<(PUBLICKEY PublicKey, PRIVATEKEY PrivateKey)> GenerateKeyPair()
        {
            System.Security.Cryptography.RSA algorithm = default;
            try
            {
                var success = false;
                Exception error = default;
                (success, error, algorithm) = AlgorithmProvider.GetAlgorithm();
                if (!success)
                    return Fail<(PUBLICKEY, PRIVATEKEY)>(error);
                var publicKey = PublicKeyCtor(algorithm.ExportRSAPublicKey());
                var privateKey = PrivateKeyCtor(algorithm.ExportRSAPrivateKey());
                return Succeed((publicKey, privateKey));
            }
            catch (Exception error)
            {
                return Fail<(PUBLICKEY, PRIVATEKEY)>(error);
            }
            finally
            {
                algorithm?.Dispose();
            }
        }
    }
}
