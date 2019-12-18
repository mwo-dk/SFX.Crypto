using FakeItEasy;
using SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA;
using System;
using Xunit;
using static FakeItEasy.A;
using static SFX.ROP.CSharp.Library;

namespace Crypto.CSharp.Tests.Infrastructure.Crypto.Asymmetric.RSA
{
    public sealed class RandomKeyPairProviderTests
    {
        #region Members
        private readonly FakeRSA _rsa;
        private readonly IRSAProvider _rsaProvider;
        #endregion

        #region Test initialization
        public RandomKeyPairProviderTests()
        {
            _rsa = new FakeRSA();
            _rsaProvider = Fake<IRSAProvider>();
            CallTo(() => _rsaProvider.GetAlgorithm())
                .Returns(Succeed(_rsa as System.Security.Cryptography.RSA));
        }
        #endregion

        #region Type tests
        [Fact]
        public void RandomKeyPairProviderImplementsIRandomKeyPairProvider() =>
            Assert.True(typeof(IRandomKeyPairProvider).IsAssignableFrom(typeof(RandomKeyPairProvider)));

        [Fact]
        public void RandomKeyPairProviderIsSealed() =>
            Assert.True(typeof(RandomKeyPairProvider).IsSealed);
        #endregion

        #region Initialization test
        [Fact]
        public void CtorWithNullProviderThrows() =>
            Assert.Throws<ArgumentNullException>(() => new RandomKeyPairProvider(default));

        [Fact]
        public void CtorSetsProvider()
        {
            var sut = Create();

            Assert.Same(_rsaProvider, sut.AlgorithmProvider);
        }
        #endregion

        #region GenerateKeyPair
        [Fact]
        public void GenerateKeyPairCreatesAlgorithm()
        {
            var sut = Create();

            sut.GenerateKeyPair();

            CallTo(() => _rsaProvider.GetAlgorithm())
                .MustHaveHappenedOnceExactly();
        }

        [Fact]
        public void GenerateKeyPairInvokesExportRSAPublicKey()
        {
            var sut = Create();

            sut.GenerateKeyPair();

            Assert.True(_rsa.ExportRSAPublicKeyInvoked);
        }

        [Fact]
        public void GenerateKeyPairExportRSAPrivateKeyInvoked()
        {
            var sut = Create();

            sut.GenerateKeyPair();

            Assert.True(_rsa.ExportRSAPrivateKeyInvoked);
        }

        [Fact]
        public void GenerateKeyPairReturnsExpected()
        {
            var sut = Create();

            var (ok, error, result) = sut.GenerateKeyPair();

            Assert.True(ok);
            Assert.Null(error);
            Assert.NotNull(result.PublicKey);
            Assert.Same(FakeRSA.ThePublicKey, result.PublicKey.Value);
            Assert.NotNull(result.PrivateKey);
            Assert.Same(FakeRSA.ThePrivateKey, result.PrivateKey.Value);
        }

        [Fact]
        public void GenerateKeyPairDisposesAlgorithm()
        {
            var sut = Create();

            sut.GenerateKeyPair();

            Assert.True(_rsa.DisposeInvoked);
        }
        #endregion

        #region Helpers
        private RandomKeyPairProvider Create() =>
            new RandomKeyPairProvider(_rsaProvider);
        #endregion
    }
}
