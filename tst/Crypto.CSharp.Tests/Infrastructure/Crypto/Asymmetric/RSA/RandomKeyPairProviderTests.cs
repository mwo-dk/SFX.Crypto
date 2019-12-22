using SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA;
using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using Xunit;

namespace Crypto.CSharp.Tests.Infrastructure.Crypto.Asymmetric.RSA
{
    public sealed class RandomKeyPairProviderTests
    {
        #region Members
        private readonly FakeRSA _rsa;
        #endregion

        #region Test initialization
        public RandomKeyPairProviderTests() =>
            _rsa = new FakeRSA();
        #endregion

        #region Type tests
        [Fact]
        public void RandomKeyPairProviderImplementsIRandomKeyPairProvider() =>
            Assert.True(typeof(IRandomKeyPairProvider<EncryptionKey, DecryptionKey>).IsAssignableFrom(typeof(RandomKeyPairProvider)));

        [Fact]
        public void RandomKeyPairProviderIsSealed() =>
            Assert.True(typeof(RandomKeyPairProvider).IsSealed);
        #endregion
    }
}
