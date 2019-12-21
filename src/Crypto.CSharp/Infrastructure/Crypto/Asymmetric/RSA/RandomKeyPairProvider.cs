using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;

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
        /// <param name="algorithmProvider">The <see cref="IRSAProvider"/></param>
        public RandomKeyPairProvider(IRSAProvider algorithmProvider) :
            base(algorithmProvider, x => new EncryptionKey(x), x => new DecryptionKey(x))
        { }
    }
}
