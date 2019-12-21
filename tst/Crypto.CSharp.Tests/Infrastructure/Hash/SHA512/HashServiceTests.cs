using FakeItEasy;
using FsCheck;
using FsCheck.Xunit;
using SFX.Crypto.CSharp.Infrastructure.Hash.SHA512;
using SFX.Crypto.CSharp.Model.Hash.SHA512;
using System;
using System.Text;
using Xunit;
using static FakeItEasy.A;
using static SFX.ROP.CSharp.Library;

namespace Crypto.CSharp.Tests.Infrastructure.Hash.SHA512
{
    public sealed class HashServiceTests
    {
        #region Members
        private readonly byte[] _hashData = new byte[] { 1, 2, 3 };
        private readonly IHashAlgorithm _hashAlgorithm;
        private readonly IHashAlgorithmProvider _hashAlgorithmProvider;

        private readonly byte[] _payloadData = new byte[] { 4, 5, 6 };
        private readonly IUnhashedPayload _payload;
        #endregion

        #region Test initialization
        public HashServiceTests()
        {
            _payload = Fake<IUnhashedPayload>();
            CallTo(() => _payload.Value).Returns(_payloadData);
            _hashAlgorithm = Fake<IHashAlgorithm>();
            CallTo(() => _hashAlgorithm.ComputeHash(_payloadData)).Returns(_hashData);
            _hashAlgorithmProvider = Fake<IHashAlgorithmProvider>();
            CallTo(() => _hashAlgorithmProvider.GetHashAlgorithm())
                .Returns(Succeed(_hashAlgorithm));
        }
        #endregion

        #region Type test
        [Fact]
        public void SHA512HashServiceImplementsIHashService() =>
            Assert.True(typeof(IHashService).IsAssignableFrom(typeof(HashService)));

        [Fact]
        public void SHA512HashServiceIsSealed() =>
            Assert.True(typeof(HashService).IsSealed);
        #endregion

        #region Initialization test
        [Fact]
        public void CtorWithHashAlgorithmProviderThrows()
        {
            Assert.Throws<ArgumentNullException>(() => new HashService(default));
        }

        [Fact]
        public void CtorSetsHashAlgorithm()
        {
            var sut = Create();

            Assert.Same(_hashAlgorithmProvider, sut.HashAlgorithmProvider);
        }
        #endregion

        #region Compute hash
        [Fact]
        public void ComputeHashWithNullPayloadFails()
        {
            var sut = Create();

            var (ok, error, result) = sut.ComputeHash(null);

            Assert.False(ok);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void ComputeHashWithInvalidPayloadFails()
        {
            CallTo(() => _payload.IsValid())
                .Returns(false);
            var sut = Create();

            var (ok, error, result) = sut.ComputeHash(_payload);

            Assert.False(ok);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void ComputeHashUtilizesHashAlgorithm()
        {
            CallTo(() => _payload.IsValid())
                .Returns(true);
            var sut = Create();

            sut.ComputeHash(_payload);

            CallTo(() => _hashAlgorithm.ComputeHash(_payloadData))
                .MustHaveHappenedOnceExactly();
        }

        [Fact]
        public void ComputeHashIfHashAlgorithmFailsFails()
        {
            var hashAlgorithm = Fake<IHashAlgorithm>();
            CallTo(() => hashAlgorithm.ComputeHash(A<byte[]>.Ignored))
                .Throws(new ObjectDisposedException(default)); https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hashalgorithm.computehash?view=netframework-4.8
            var hashAlgorithmProvider = Fake<IHashAlgorithmProvider>();
            CallTo(() => hashAlgorithmProvider.GetHashAlgorithm())
                .Returns(Succeed(hashAlgorithm));
            CallTo(() => _payload.IsValid())
                .Returns(true);
            var sut = new HashService(hashAlgorithmProvider);

            sut.ComputeHash(_payload);

            var (ok, error, result) = sut.ComputeHash(_payload);

            Assert.False(ok);
            Assert.NotNull(error);
            Assert.IsType<ObjectDisposedException>(error);
            Assert.Null(result);
        }

        [Property]
        public Property ComputeHashWorks(NonEmptyString data)
        {
            var payload = new UnhashedPayload(Encoding.UTF8.GetBytes(data.Get));
            var hashAlgorithmProvider = new HashAlgorithmProvider();
            var sut = new HashService(hashAlgorithmProvider);

            var (ok, error, result) = sut.ComputeHash(payload);

            return (ok && error is null && !(result is null) && !(result.Value is null) && result.Value.Length > 0).ToProperty();
        }

        [Fact]
        public void ComputeHashDisposesOfHashAlgorithm()
        {
            CallTo(() => _payload.IsValid())
                .Returns(true);
            var sut = Create();

            sut.ComputeHash(_payload);

            CallTo(() => _hashAlgorithm.Dispose())
                .MustHaveHappenedOnceExactly();
        }
        #endregion

        #region Helpers
        private HashService Create() =>
            new HashService(_hashAlgorithmProvider);
        #endregion
    }
}
