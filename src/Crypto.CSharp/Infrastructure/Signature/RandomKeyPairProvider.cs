using SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA;
using SFX.Crypto.CSharp.Model.Signature;
using System.Security.Cryptography;

namespace SFX.Crypto.CSharp.Infrastructure.Signature
{
    /// <summary>
    /// Specialization of <see cref="IRandomKeyPairProvider{PUBLICKEY, PRIVATEKEY}"/>
    /// for <see cref="EncryptionKey"/> and <see cref="DecryptionKey"/> respectively
    /// </summary>
    public sealed class RandomKeyPairProvider :
        RandomKeyPairProviderBase<VerificationKey, SigningKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public RandomKeyPairProvider() :
            base(x => new VerificationKey(x), x => new SigningKey(x)) =>
            RandomKeyPairProviderExtensions
                .WithAlgorithm<RandomKeyPairProvider, VerificationKey, SigningKey>(this, new RSACryptoServiceProvider());
    }
}
