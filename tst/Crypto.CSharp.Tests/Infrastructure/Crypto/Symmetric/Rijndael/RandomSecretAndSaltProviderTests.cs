using SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Rijndael;
using Xunit;

namespace Crypto.CSharp.Tests.Infrastructure.Crypto.Symmetric.Rijndael
{
    public sealed class RandomSecretAndSaltProviderTests
    {
        #region Members
        private readonly FakeAes _aes;
        #endregion

        #region Test initialization
        public RandomSecretAndSaltProviderTests()
        {
            _aes = new FakeAes();
        }
        #endregion

        #region Type tests
        [Fact]
        public void RandomSecretAndSaltProviderImplementsIRandomSecretAndSaltProvider() =>
            Assert.True(typeof(IRandomSecretAndSaltProvider).IsAssignableFrom(typeof(RandomSecretAndSaltProvider)));

        [Fact]
        public void RandomSecretAndSaltProviderIsSealed() =>
            Assert.True(typeof(RandomSecretAndSaltProvider).IsSealed);
        #endregion
    }
}
