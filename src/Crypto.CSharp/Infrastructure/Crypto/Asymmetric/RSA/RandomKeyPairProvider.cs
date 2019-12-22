using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using System.Security.Cryptography;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Specialization of <see cref="IRandomKeyPairProvider{PUBLICKEY, PRIVATEKEY}"/>
    /// for <see cref="EncryptionKey"/> and <see cref="DecryptionKey"/> respectively
    /// </summary>
    public sealed class RandomKeyPairProvider :
        RandomKeyPairProviderBase<EncryptionKey, DecryptionKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public RandomKeyPairProvider() :
            base(x => new EncryptionKey(x), x => new DecryptionKey(x)) =>
            RandomKeyPairProviderExtensions
                .WithAlgorithm<RandomKeyPairProvider, EncryptionKey, DecryptionKey>(this, new RSACryptoServiceProvider());
    }
}
