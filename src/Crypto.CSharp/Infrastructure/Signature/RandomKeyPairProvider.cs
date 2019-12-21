using SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA;
using SFX.Crypto.CSharp.Model.Signature;

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
        /// <param name="algorithmProvider">The <see cref="IRSAProvider"/></param>
        public RandomKeyPairProvider(IRSAProvider algorithmProvider) :
            base(algorithmProvider, x => new SigningKey(x), x => new VerificationKey(x))
        { }
    }
}
