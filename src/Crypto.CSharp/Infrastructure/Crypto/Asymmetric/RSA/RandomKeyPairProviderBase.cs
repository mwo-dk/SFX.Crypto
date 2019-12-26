using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
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

        protected RandomKeyPairProviderBase(Func<byte[], PUBLICKEY> publicKeyCtor,
            Func<byte[], PRIVATEKEY> privateKeyCtor)
        {
            PublicKeyCtor = publicKeyCtor ?? throw new ArgumentNullException(nameof(publicKeyCtor));
            PrivateKeyCtor = privateKeyCtor ?? throw new ArgumentNullException(nameof(privateKeyCtor));
        }

        internal Func<byte[], PUBLICKEY> PublicKeyCtor { get; }
        internal Func<byte[], PRIVATEKEY> PrivateKeyCtor { get; }

        /// <inheritdoc/>
        public Result<(PUBLICKEY PublicKey, PRIVATEKEY PrivateKey)> GenerateKeyPair()
        {
            if (Algorithm is null)
                return Fail<(PUBLICKEY, PRIVATEKEY)>(new InvalidOperationException("RandomKeyPRovider is not initialized"));
            try
            {
                var publicKey = PublicKeyCtor(Algorithm.ExportRSAPublicKey());
                var privateKey = PrivateKeyCtor(Algorithm.ExportRSAPrivateKey());
                return Succeed((publicKey, privateKey));
            }
            catch (Exception error)
            {
                return Fail<(PUBLICKEY, PRIVATEKEY)>(error);
            }
        }

        internal System.Security.Cryptography.RSA Algorithm;
    }

    public static class RandomKeyPairProviderExtensions
    {
        public static Service WithAlgorithm<Service, PublicKey, PrivateKey>(this Service service,
            System.Security.Cryptography.RSA algorithm)
            where Service : RandomKeyPairProviderBase<PublicKey, PrivateKey>
        {
            if (!(service.Algorithm is null) && !ReferenceEquals(service.Algorithm, algorithm))
                service.Algorithm.Dispose();

            service.Algorithm = algorithm;
            return service;
        }

        public static Service WithRSACryptoServiceProvider<Service, PublicKey, PrivateKey>(this Service service)
            where Service : RandomKeyPairProviderBase<PublicKey, PrivateKey>
        {
            if (!(service.Algorithm is null))
                service.Algorithm.Dispose();

            service.Algorithm = new RSACryptoServiceProvider();
            return service;
        }
    }
}
