using SFX.Crypto.CSharp.Infrastructure.Hash.SHA512;
using SFX.Utils.Infrastructure;
using System;
using Xunit;
using static FakeItEasy.A;

namespace Crypto.CSharp.Tests.Infrastructure.Hash.SHA512
{
    public sealed class HashAlgorithmProviderTests
    {
        #region Type test
        [Fact]
        public void HashAlgorithmProviderImplementsIHashService() =>
            Assert.True(typeof(IHashAlgorithmProvider).IsAssignableFrom(typeof(HashAlgorithmProvider)));

        [Fact]
        public void HashAlgorithmProviderIsSealed() =>
            Assert.True(typeof(HashAlgorithmProvider).IsSealed);
        #endregion

        #region GetHashAlgorithm
        [Fact]
        public void GetHashAlgorithmWorks()
        {
            var sut = Create();

            var (ok, error, result) = sut.GetHashAlgorithm();

            Assert.True(ok);
            Assert.Null(error);
            Assert.NotNull(result);
            Assert.IsType<HashAlgorithm>(result);
            var result_ = result as HashAlgorithm;
            Assert.True((result as IInitializable).IsInitialized());
        }
        #endregion

        #region Helpers
        private HashAlgorithmProvider Create() =>
            new HashAlgorithmProvider();
        #endregion
    }
}
