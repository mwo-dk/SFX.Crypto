using FakeItEasy;
using FsCheck;
using FsCheck.Xunit;
using SFX.Crypto.CSharp.Infrastructure.Hash.SHA512;
using SFX.Crypto.CSharp.Infrastructure.Signature;
using SFX.Crypto.CSharp.Model.Hash.SHA512;
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
        private readonly IPayload _payload;
        private readonly SFX.Crypto.CSharp.Model.Signature.IHash _hash;
        private readonly ISignature _signature;
        private readonly ISigningKey _signingKey;
        private readonly IVerificationKey _verificationKey;
        #endregion

        #region Test initialization
        public SignatureServiceTests()
        {
            _keyProvider = new RandomKeyPairProvider(new SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA.RSACryptoSvcProvider());
            _payload = Fake<IPayload>();
            _hash = Fake<SFX.Crypto.CSharp.Model.Signature.IHash>();
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
            var sut = Create();

            var (success, error, result) = sut.SignPayload(default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void SignPayloadWithInvalidPayloadFails()
        {
            CallTo(() => _payload.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.SignPayload(_payload);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void SignPayloadWithInvalidKeyFails()
        {
            CallTo(() => _signingKey.IsValid())
                .Returns(false);
            var sut = Create();

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
            var sut = Create();

            var (success, error, result) = sut.SignHash(default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void SignHashWithInvalidPayloadFails()
        {
            CallTo(() => _hash.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.SignHash(_hash);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Null(result);
        }

        [Fact]
        public void SignHashWithInvalidKeyFails()
        {
            CallTo(() => _signingKey.IsValid())
                .Returns(false);
            var sut = Create();

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
            var sut = Create();

            var (success, error, result) = sut.VerifyPayload(default, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyPayloadWithInvalidPayloadFails()
        {
            CallTo(() => _payload.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.VerifyPayload(_payload, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyPayloadWithNullSignatureFails()
        {
            var sut = Create();

            var (success, error, result) = sut.VerifyPayload(_payload, default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyPayloadWithInvalidSignatureFails()
        {
            CallTo(() => _signature.IsValid())
                .Returns(false);
            var sut = Create();

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
            var sut = Create();

            var (success, error, result) = sut.VerifyHash(default, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyHashWithInvalidPayloadFails()
        {
            CallTo(() => _hash.IsValid())
                .Returns(false);
            var sut = Create();

            var (success, error, result) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyHashWithNullSignatureFails()
        {
            var sut = Create();

            var (success, error, result) = sut.VerifyHash(_hash, default);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyHashWithInvalidSignatureFails()
        {
            CallTo(() => _signature.IsValid())
                .Returns(false);
            var sut = Create();

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
            var payload = new UnhashedPayload(Encoding.UTF8.GetBytes(data.Get));
            var hashService =
                new HashService(new HashAlgorithmProvider());
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
