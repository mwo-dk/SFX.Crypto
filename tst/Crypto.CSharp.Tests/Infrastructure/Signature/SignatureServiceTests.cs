using FakeItEasy;
using FsCheck;
using FsCheck.Xunit;
using SFX.Crypto.CSharp.Infrastructure.Hashing;
using SFX.Crypto.CSharp.Infrastructure.Signature;
using SFX.Crypto.CSharp.Model.Signature;
using System;
using System.Text;
using Xunit;
using static FakeItEasy.A;

namespace Crypto.CSharp.Tests.Infrastructure.Signature
{
    public class SignatureServiceTests
    {
        #region Members
        private readonly RandomKeyPairProvider _keyProvider;
        private readonly SFX.Crypto.CSharp.Model.Signature.IPayload _payload;
        private readonly SFX.Crypto.CSharp.Model.Signature.IHash _hash;
        private readonly ISignature _signature;
        private readonly ISigningKey _signingKey;
        private readonly IVerificationKey _verificationKey;
        #endregion

        #region Test initialization
        public SignatureServiceTests()
        {
            _keyProvider = new RandomKeyPairProvider();
            _payload = Fake<IPayload>();
            _hash = Fake<IHash>();
            _signature = Fake<ISignature>();
            _signingKey = Fake<ISigningKey>();
            _verificationKey = Fake<IVerificationKey>();
        }
        #endregion

        #region Type test
        [Fact]
        public void SignatureServiceIsSealed() =>
            Assert.True(typeof(SignatureService).IsSealed);
        #endregion

        #region SignPayload
        [Fact]
        public void SignPayloadUnInitializedFails()
        {
            var sut = new SignatureService();

            var (success, error, result) = sut.SignPayload(_payload);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);

            sut = new SignatureService().WithSHA512();

            (success, error, result) = sut.SignPayload(_payload);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);

            sut = new SignatureService().WithPkcs1();

            (success, error, result) = sut.SignPayload(_payload);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);
        }

        [Fact]
        public void SignPayloadWithNullPayloadFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);

            var (success, error, result) = sut.SignPayload(default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void SignPayloadWithInvalidPayloadFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);
            CallTo(() => _payload.IsValid())
                .Returns(false);

            var (success, error, result) = sut.SignPayload(_payload);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }
        #endregion

        #region SignHash
        [Fact]
        public void SignPHashUnInitializedFails()
        {
            var sut = new SignatureService();

            var (success, error, result) = sut.SignHash(_hash);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);

            sut = new SignatureService().WithSHA512();

            (success, error, result) = sut.SignHash(_hash);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);

            sut = new SignatureService().WithPkcs1();

            (success, error, result) = sut.SignHash(_hash);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);
        }

        [Fact]
        public void SignHashWithNullPayloadFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);

            var (success, error, result) = sut.SignHash(default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void SignHashWithInvalidPayloadFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            CallTo(() => _hash.IsValid())
                .Returns(false);
            var sut = Create(publicKey, privateKey);

            var (success, error, result) = sut.SignHash(_hash);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }
        #endregion

        #region VerifyPayload
        [Fact]
        public void VerifyPayloadUnInitializedFails()
        {
            var sut = new SignatureService();

            var (success, error, result) = sut.VerifyPayload(_payload, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);

            sut = new SignatureService().WithSHA512();

            (success, error, result) = sut.VerifyPayload(_payload, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);

            sut = new SignatureService().WithPkcs1();

            (success, error, result) = sut.VerifyPayload(_payload, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);
        }

        [Fact]
        public void VerifyPayloadWithNullPayloadFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);

            var (success, error, result) = sut.VerifyPayload(default, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyPayloadWithInvalidPayloadFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);
            CallTo(() => _payload.IsValid())
                .Returns(false);

            var (success, error, result) = sut.VerifyPayload(_payload, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyPayloadWithNullSignatureFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);

            var (success, error, result) = sut.VerifyPayload(_payload, default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyPayloadWithInvalidSignatureFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);
            CallTo(() => _signature.IsValid())
                .Returns(false);

            var (success, error, result) = sut.VerifyPayload(_payload, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }
        #endregion

        #region VerifyHash
        [Fact]
        public void VerifyHashUnInitializedFails()
        {
            var sut = new SignatureService();

            var (success, error, result) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);

            sut = new SignatureService().WithSHA512();

            (success, error, result) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);

            sut = new SignatureService().WithPkcs1();

            (success, error, result) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);
        }

        [Fact]
        public void VerifyHashWithNullPayloadFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);

            var (success, error, result) = sut.VerifyHash(default, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyHashWithInvalidPayloadFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);
            CallTo(() => _hash.IsValid())
                .Returns(false);

            var (success, error, result) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyHashWithNullSignatureFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);

            var (success, error, result) = sut.VerifyHash(_hash, default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyHashWithInvalidSignatureFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);
            CallTo(() => _signature.IsValid())
                .Returns(false);

            var (success, error, result) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }
        #endregion

        #region Roundtrip works
        [Property]
        public Property RoundtripForSigningDataWorks(NonEmptyString data)
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var payload = new Payload(Encoding.UTF8.GetBytes(data.Get));
            var sut = Create(publicKey, privateKey);

            var (signOk, signError, signature) =
                sut.SignPayload(payload);
            var (verifyOk, verifyError, result) =
                sut.VerifyPayload(payload, signature);

            return (signOk && signError is null && !(signature is null) &&
                verifyOk && verifyError is null && result).ToProperty();
        }

        [Property]
        public Property RoundtripForSigningHashWorks(NonEmptyString data)
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var payload = new SFX.Crypto.CSharp.Model.Hashing.Payload(Encoding.UTF8.GetBytes(data.Get));
            var hashService =
                new HashService().WithSHA512CryptoServiceProvider();
            var hash_ = hashService.ComputeHash(payload);
            var hash = new SFX.Crypto.CSharp.Model.Signature.Hash(hash_.Value.Value);
            var sut = Create(publicKey, privateKey);

            var (signOk, signError, signature) =
                sut.SignHash(hash);
            var (verifyOk, verifyError, result) =
                sut.VerifyHash(hash, signature);

            return (signOk && signError is null && !(signature is null) &&
                verifyOk && verifyError is null && result).ToProperty();
        }
        #endregion

        #region Helpers
        private SignatureService Create() =>
            new SignatureService()
            .WithSHA512()
            .WithPkcs1()
            .WithSigningKey(_signingKey)
            .WithVerificationKey(_verificationKey);
        private SignatureService Create(ISigningKey signingKey, IVerificationKey verificationKey) =>
            new SignatureService()
            .WithSHA512()
            .WithPkcs1()
            .WithSigningKey(signingKey)
            .WithVerificationKey(verificationKey);

        private (SigningKey Public, VerificationKey Private) CreateKeyPair() =>
            _keyProvider.GenerateKeyPair();
        #endregion
    }
}
