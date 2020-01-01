using FakeItEasy;
using SFX.Crypto.CSharp.Infrastructure.Hashing;
using SFX.Crypto.CSharp.Model.Hashing;
using Xunit;
using static FakeItEasy.A;

namespace Crypto.CSharp.Tests.Infrastructure.Hash
{
    public sealed class HashServiceTests
    {
        #region Members
        private readonly byte[] _hashData = new byte[] { 1, 2, 3 };

        private readonly byte[] _payloadData = new byte[] { 4, 5, 6 };
        private readonly IPayload _payload;
        #endregion

        #region Test initialization
        public HashServiceTests()
        {
            _payload = Fake<IPayload>();
            CallTo(() => _payload.Value).Returns(_payloadData);
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

        #region Compute hash
        [Fact]
        public void ComputeHashWithNullPayloadFails()
        {
            var sut = Create();

            var (ok, result, error) = sut.ComputeHash(null);

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

            var (ok, result, error) = sut.ComputeHash(_payload);

            Assert.False(ok);
            Assert.NotNull(error);
            Assert.Null(result);
        }
        #endregion

        #region Helpers
        private HashService Create() =>
            new HashService();
        #endregion
    }
}
