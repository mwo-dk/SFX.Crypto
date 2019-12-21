using FakeItEasy;
using SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes;
using System;
using Xunit;
using static FakeItEasy.A;
using static SFX.ROP.CSharp.Library;

namespace Crypto.CSharp.Tests.Infrastructure.Crypto.Symmetric.Aes
{
    public sealed class RandomSecretAndSaltProviderTests
    {
        #region Members
        private readonly FakeAes _aes;
        private readonly IAesProvider _aesProvider;
        #endregion

        #region Test initialization
        public RandomSecretAndSaltProviderTests()
        {
            _aes = new FakeAes();
            _aesProvider = Fake<IAesProvider>();
            CallTo(() => _aesProvider.GetAlgorithm())
                .Returns(Succeed(_aes as System.Security.Cryptography.Aes));
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

        #region Initialization test
        [Fact]
        public void CtorWithNullProviderThrows() =>
            Assert.Throws<ArgumentNullException>(() => new RandomSecretAndSaltProvider(default));

        [Fact]
        public void CtorSetsProvider()
        {
            var sut = Create();

            Assert.Same(_aesProvider, sut.AlgorithmProvider);
        }
        #endregion

        #region GenerateKeyPair
        [Fact]
        public void GenerateKeyPairCreatesAlgorithm()
        {
            var sut = Create();

            sut.GenerateKeyPair();

            CallTo(() => _aesProvider.GetAlgorithm())
                .MustHaveHappenedOnceExactly();
        }

        [Fact]
        public void GenerateKeyPairInvokesGeneratesKey()
        {
            var sut = Create();

            sut.GenerateKeyPair();

            Assert.True(_aes.GenerateKeyInvoked);
        }

        [Fact]
        public void GenerateKeyPairInvokesGeneratesIV()
        {
            var sut = Create();

            sut.GenerateKeyPair();

            Assert.True(_aes.GenerateIVInvoked);
        }

        [Fact]
        public void GenerateKeyPairReturnsExpected()
        {
            var sut = Create();

            var (ok, error, result) = sut.GenerateKeyPair();

            Assert.True(ok);
            Assert.Null(error);
            Assert.NotNull(result.Secret);
            Assert.Same(FakeAes.TheKey, result.Secret.Value);
            Assert.NotNull(result.Salt);
            Assert.Same(FakeAes.TheIV, result.Salt.Value);
        }

        [Fact]
        public void GenerateKeyPairDisposesAlgorithm()
        {
            var sut = Create();

            sut.GenerateKeyPair();

            Assert.True(_aes.DisposeInvoked);
        }
        #endregion

        #region Helpers
        private RandomSecretAndSaltProvider Create() =>
            new RandomSecretAndSaltProvider(_aesProvider);
        #endregion
    }
}
