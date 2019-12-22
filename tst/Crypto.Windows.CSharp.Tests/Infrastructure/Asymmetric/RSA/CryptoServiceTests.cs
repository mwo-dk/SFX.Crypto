using FakeItEasy;
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
        private readonly RandomKeyPairProvider _keyProvider;

        private readonly IUnencryptedPayload _payload;
        private readonly IEncryptionKey _encryptionKey;
        private readonly IEncryptedPayload _coded;
        private readonly IDecryptionKey _decryptionKey;
        #endregion

        #region Test initialization
        public CryptoServiceTests()
        {
            _keyProvider = new RandomKeyPairProvider().WithRSACng();

            _payload = Fake<IUnencryptedPayload>();
            _encryptionKey = Fake<IEncryptionKey>();
            _coded = Fake<IEncryptedPayload>();
            _decryptionKey = Fake<IDecryptionKey>();
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

            var (success, error, result) = sut.Encrypt(default, _encryptionKey);

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

            var (success, error, result) = sut.Encrypt(_payload, _encryptionKey);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void EncryptWithNullKeyFails()
        {
            var sut = Create();

            var (success, error, result) = sut.Encrypt(_payload, default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void EncryptWithInvalidKayFails()
        {
            CallTo(() => _encryptionKey.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.Encrypt(_payload, _encryptionKey);

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

            var (success, error, result) = sut.Decrypt(default, _decryptionKey);

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

            var (success, error, result) = sut.Decrypt(_coded, _decryptionKey);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void DecryptWithNullKeyFails()
        {
            var sut = Create();

            var (success, error, result) = sut.Decrypt(_coded, default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void DecryptWithInvalidKeyFails()
        {
            CallTo(() => _decryptionKey.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.Decrypt(_coded, _decryptionKey);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }
        #endregion

        #region Roundtrip works
        [Property]
        public Property RoundtripWorks(NonEmptyString data)
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var payload = new UnencryptedPayload(Encoding.UTF8.GetBytes(data.Get));
            var sut = Create();

            var (_, _, coded) = sut.Encrypt(payload, publicKey);
            var (_, _, unencoded) = sut.Decrypt(coded, privateKey);

            var result = Encoding.UTF8.GetString(unencoded.Value);

            return (0 == string.Compare(data.Get, result, StringComparison.InvariantCulture)).ToProperty();
        }
        #endregion

        #region Helpers
        private CryptoService Create() =>
            new CryptoService().WithRSACng();

        private (EncryptionKey Public, DecryptionKey Private) CreateKeyPair() =>
            _keyProvider.GenerateKeyPair();
        #endregion
    }
}
