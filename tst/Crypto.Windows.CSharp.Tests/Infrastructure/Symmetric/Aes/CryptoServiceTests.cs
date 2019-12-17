using FakeItEasy;
using FsCheck;
using FsCheck.Xunit;
using SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes;
using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes;
using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using static FakeItEasy.A;

namespace Crypto.Windows.CSharp.Tests.Infrastructure.Symmetric.Aes
{
    public abstract class AesCryptoServiceTests<Service> where Service : ICryptoService
    {
        #region Members
        private readonly Func<Service> _ctor;
        private readonly Func<(Secret Secret, Salt Salt)> _keyProvider;

        private readonly IUnencryptedPayload _payload;

        private readonly IEncryptedPayload _coded;
        private readonly ISecret _secret;
        private readonly ISalt _salt;
        #endregion

        #region Test initialization
        protected AesCryptoServiceTests(Func<Service> ctor,
            Func<(Secret Secret, Salt Salt)> keyProvider)
        {
            _ctor = ctor;
            _keyProvider = keyProvider;

            _payload = Fake<IUnencryptedPayload>();
            _coded = Fake<IEncryptedPayload>();
            _secret = Fake<ISecret>();
            _salt = Fake<ISalt>();
        }
        #endregion

        #region Type test
        [Fact]
        public void CryptoServiceImplementsICryptoService() =>
            Assert.True(typeof(ICryptoService).IsAssignableFrom(typeof(AesCryptoServiceProviderBasedCryptoService)));

        [Fact]
        public void CryptoServiceIsSealed() =>
            Assert.True(typeof(AesCryptoServiceProviderBasedCryptoService).IsSealed);
        #endregion

        #region Encrypt
        [Fact]
        public void EncryptWithNullPayloadFails()
        {
            var sut = Create();

            var (success, error, result) = sut.Encrypt(default, _secret, _salt);

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

            var (success, error, result) = sut.Encrypt(_payload, _secret, _salt);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void EncryptWithNullSecretFails()
        {
            var sut = Create();

            var (success, error, result) = sut.Encrypt(_payload, default, _salt);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void EncryptWithInvalidSecretFails()
        {
            CallTo(() => _secret.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.Encrypt(_payload, _secret, _salt);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void EncryptWithNullSaltFails()
        {
            var sut = Create();

            var (success, error, result) = sut.Encrypt(_payload, _secret, default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void EncryptWithInvalidSaltFails()
        {
            CallTo(() => _secret.IsValid())
                .Returns(true);
            CallTo(() => _salt.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.Encrypt(_payload, _secret, _salt);

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

            var (success, error, result) = sut.Decrypt(default, _secret, _salt);

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

            var (success, error, result) = sut.Decrypt(_coded, _secret, _salt);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void DecryptWithNullSecretFails()
        {
            var sut = Create();

            var (success, error, result) = sut.Decrypt(_coded, default, _salt);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void DecryptWithInvaliSecretFails()
        {
            CallTo(() => _secret.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.Decrypt(_coded, _secret, _salt);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void DecryptWithNullSaltFails()
        {
            var sut = Create();

            var (success, error, result) = sut.Decrypt(_coded, _secret, default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void DecryptWithInvaliSaltFails()
        {
            CallTo(() => _secret.IsValid())
                .Returns(true);
            CallTo(() => _salt.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.Decrypt(_coded, _secret, _salt);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }
        #endregion

        #region Roundtrip works
        [Property]
        public Property RoundtripWorks(NonEmptyString data)
        {
            var (secret, salt) = CreateKeyPair();
            var payload = new UnencryptedPayload(Encoding.UTF8.GetBytes(data.Get));
            var sut = Create();

            var (_, _, coded) = sut.Encrypt(payload, secret, salt);
            var (_, _, unencoded) = sut.Decrypt(coded, secret, salt);

            var result = Encoding.UTF8.GetString(unencoded.Value);

            return (0 == string.Compare(data.Get, result, StringComparison.InvariantCulture)).ToProperty();
        }
        #endregion

        #region Helpers
        private Service Create() => _ctor();

        private (Secret Secret, Salt Salt) CreateKeyPair() =>
            _keyProvider();
        #endregion
    }
    public sealed class AesCngBasedCryptoServiceTests :
        AesCryptoServiceTests<AesCngBasedCryptoService>
    {
        public AesCngBasedCryptoServiceTests() : base(Ctor, CreateKeyPair) { }

        private static AesCngBasedCryptoService Ctor() =>
            new AesCngBasedCryptoService();

        private static (Secret Secret, Salt Salt) CreateKeyPair()
        {
            using var provider = new AesCng();
            provider.GenerateKey();
            provider.GenerateIV();
            return (new Secret(provider.Key),
                new Salt(provider.IV));
        }
    }
}
