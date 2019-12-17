using FakeItEasy;
using SFX.Crypto.CSharp.Infrastructure.Hash.SHA512;
using SFX.Crypto.CSharp.Model.Hash.SHA512;
using SFX.ROP.CSharp;
using System;
using Xunit;
using static FakeItEasy.A;
using static SFX.ROP.CSharp.Library;
namespace Crypto.CSharp.Tests.Infrastructure.Hash.SHA512
{
    public sealed class HashAlgorithmTests
    {
        #region Members
        private readonly byte[] _hashData = new byte[] { 1, 2, 3 };
        private readonly IHashAlgorithm _hashAlgorithm;
        private readonly IHashAlgorithmProvider _hashAlgorithmProvider;

        private readonly byte[] _payloadData = new byte[] { 4, 5, 6 };
        private readonly IUnhashedPayload _payload;
        #endregion

        #region Test initialization
        public HashAlgorithmTests()
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
        public void HashAlgorithmImplementsIHashService() =>
            Assert.True(typeof(IHashAlgorithm).IsAssignableFrom(typeof(HashAlgorithm)));

        [Fact]
        public void HashAlgorithmIsSealed() =>
            Assert.True(typeof(HashAlgorithm).IsSealed);
        #endregion

        #region Helpers
        private HashAlgorithm Create() =>
            new HashAlgorithm();
        #endregion
    }
}
