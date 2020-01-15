using SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA;
using SFX.Crypto.CSharp.Model.Signature;
using Xunit;
using RandomKeyPairProvider = SFX.Crypto.CSharp.Infrastructure.Signature.RandomKeyPairProvider;

namespace Crypto.CSharp.Tests.Infrastructure.Signature
{
    public sealed class RandomKeyPairProviderTests
    {
        #region Members
        private readonly FakeRSA _rsa;
        #endregion

        #region Test initialization
        public RandomKeyPairProviderTests()
        {
            _rsa = new FakeRSA();
        }
        #endregion

        #region Type tests
        [Fact]
        public void RandomKeyPairProviderImplementsIRandomKeyPairProvider() =>
            Assert.True(typeof(IRandomKeyPairProvider<VerificationKey, SigningKey>).IsAssignableFrom(typeof(RandomKeyPairProvider)));

        [Fact]
        public void RandomKeyPairProviderIsSealed() =>
            Assert.True(typeof(RandomKeyPairProvider).IsSealed);
        #endregion
    }
}
