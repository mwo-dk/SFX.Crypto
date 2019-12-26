﻿using FakeItEasy;
using FsCheck;
using FsCheck.Xunit;
using SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA;
using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using System;
using System.Text;
using Xunit;
using static FakeItEasy.A;

namespace Crypto.Windows.CSharp.Tests.Infrastructure.Asymmetric.RSA
{
    public class CryptoServiceTests
    {
        #region Members
        private readonly RandomKeyPairProvider _keyPairProvider;
        private readonly IUnencryptedPayload _payload;
        private readonly IEncryptedPayload _coded;
        #endregion

        #region Test initialization
        public CryptoServiceTests()
        {
            _keyPairProvider = new RandomKeyPairProvider();
            _payload = Fake<IUnencryptedPayload>();
            _coded = Fake<IEncryptedPayload>();
        }
        #endregion

        #region Type test
        [Fact]
        public void CryptoServiceImplementsICryptoService() =>
            Assert.True(typeof(ICryptoService).IsAssignableFrom(typeof(CryptoService)));

        [Fact]
        public void CryptoServiceIsSealed() =>
            Assert.True(typeof(CryptoService).IsSealed);
        #endregion

        #region Encrypt
        [Fact]
        public void EncryptWithNullPayloadFails()
        {
            var sut = Create();

            var (success, error, result) = sut.Encrypt(default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void EncryptWithInvalidPayloadFails()
        {
            CallTo(() => _payload.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.Encrypt(_payload);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }
        #endregion

        #region Decrypt
        [Fact]
        public void DecryptWithNullPayloadFails()
        {
            var sut = Create();

            var (success, error, result) = sut.Decrypt(default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void DecryptWithInvalidPayloadFails()
        {
            CallTo(() => _payload.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.Decrypt(_coded);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }
        #endregion

        #region Roundtrip works
        [Property]
        public Property RoundtripWorks(NonEmptyString data)
        {
            var (ok, _, keys) =
                _keyPairProvider.GenerateKeyPair();
            if (!ok)
                return false.ToProperty();
            var (encryptionKey, decryptionKey) = keys;
            var payload = new UnencryptedPayload(Encoding.UTF8.GetBytes(data.Get));
            var sut = Create()
                .WithEncryptionKey(encryptionKey)
                .WithDeryptionKey(decryptionKey);

            var (_, _, coded) = sut.Encrypt(payload);
            var (_, _, unencoded) = sut.Decrypt(coded);

            var result = Encoding.UTF8.GetString(unencoded.Value);

            return (0 == string.Compare(data.Get, result, StringComparison.InvariantCulture)).ToProperty();
        }
        #endregion

        #region Helpers
        private CryptoService Create() =>
            new CryptoService().WithRSACng();
        #endregion
    }
}
