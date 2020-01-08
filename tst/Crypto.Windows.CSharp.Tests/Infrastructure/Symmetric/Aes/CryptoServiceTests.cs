using FakeItEasy;
using FsCheck;
using FsCheck.Xunit;
using SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes;
using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes;
using System;
using System.Text;
using Xunit;
using static FakeItEasy.A;

namespace Crypto.Windows.CSharp.Tests.Infrastructure.Symmetric.Aes
{
    public sealed class CryptoServiceTests
    {
        #region Members
        private readonly RandomSecretAndSaltProvider _keyProvider;
        private readonly IUnencryptedPayload _payload;

        private readonly IEncryptedPayload _coded;
        private readonly ISecret _secret;
        private readonly ISalt _salt;
        #endregion

        #region Test initialization
        public CryptoServiceTests()
        {
            _keyProvider = new RandomSecretAndSaltProvider();
            _keyProvider.WithAesCng();

            _payload = Fake<IUnencryptedPayload>();
            _coded = Fake<IEncryptedPayload>();
            _secret = Fake<ISecret>();
            _salt = Fake<ISalt>();
        }
        #endregion

        #region Encrypt
        [Fact]
        public void EncryptWithNullPayloadFails()
        {
            var sut = Create();

            var (success, result, error) = sut.Encrypt(default);

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

            var (success, result, error) = sut.Encrypt(_payload);

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

            var (success, result, error) = sut.Decrypt(default);

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

            var (success, result, error) = sut.Decrypt(_coded);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }
        #endregion

        #region Roundtrip works
        [Property]
        public Property RoundtripWorks(NonEmptyString data)
        {
            var payload = new UnencryptedPayload(Encoding.UTF8.GetBytes(data.Get));
            var sut = Create();

            var (_, coded, _) = sut.Encrypt(payload);
            var (_, unencoded, _) = sut.Decrypt(coded);

            var result = Encoding.UTF8.GetString(unencoded.Value);

            return (0 == string.Compare(data.Get, result, StringComparison.InvariantCulture)).ToProperty();
        }
        #endregion

        #region Helpers
        private CryptoService Create()
        {
            var result = new CryptoService();
            result.WithAesCng();
            return result;
        }

        private (ISecret Secret, ISalt Salt) CreateKeyPair() =>
            _keyProvider.GenerateKeyPair();
        #endregion
    }
}
