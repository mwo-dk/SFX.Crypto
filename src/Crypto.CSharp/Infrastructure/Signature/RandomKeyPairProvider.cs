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
        RandomKeyPairProviderBase<SigningKey, VerificationKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public RandomKeyPairProvider() :
            base(x => new SigningKey(x), x => new VerificationKey(x)) =>
            RandomKeyPairProviderExtensions
                .WithAlgorithm<RandomKeyPairProvider, SigningKey, VerificationKey>(this, new RSACryptoServiceProvider());
    }
}
