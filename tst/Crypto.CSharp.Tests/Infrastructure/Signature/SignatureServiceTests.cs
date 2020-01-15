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
        private readonly IPayload _payload;
        private readonly IHash _hash;
        private readonly ISignature _signature;
        #endregion

        #region Test initialization
        public SignatureServiceTests()
        {
            _keyProvider = new RandomKeyPairProvider();
            _payload = Fake<IPayload>();
            _hash = Fake<IHash>();
            _signature = Fake<ISignature>();
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

            var (success, result, error) = sut.SignPayload(_payload);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);

            sut = new SignatureService().WithSHA512();

            (success, result, error) = sut.SignPayload(_payload);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);

            sut = new SignatureService().WithPkcs1();

            (success, result, error) = sut.SignPayload(_payload);

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

            var (success, result, error) = sut.SignPayload(default);

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

            var (success, result, error) = sut.SignPayload(_payload);

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

            var (success, result, error) = sut.SignHash(_hash);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);

            sut = new SignatureService().WithSHA512();

            (success, result, error) = sut.SignHash(_hash);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.Null(result);

            sut = new SignatureService().WithPkcs1();

            (success, result, error) = sut.SignHash(_hash);

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

            var (success, result, error) = sut.SignHash(default);

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

            var (success, result, error) = sut.SignHash(_hash);

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

            var (success, result, error) = sut.VerifyPayload(_payload, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);

            sut = new SignatureService().WithSHA512();

            (success, result, error) = sut.VerifyPayload(_payload, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);

            sut = new SignatureService().WithPkcs1();

            (success, result, error) = sut.VerifyPayload(_payload, _signature);

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

            var (success, result, error) = sut.VerifyPayload(default, _signature);

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

            var (success, result, error) = sut.VerifyPayload(_payload, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyPayloadWithNullSignatureFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);

            var (success, result, error) = sut.VerifyPayload(_payload, default);

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

            var (success, result, error) = sut.VerifyPayload(_payload, _signature);

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

            var (success, result, error) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);

            sut = new SignatureService().WithSHA512();

            (success, result, error) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.True(error is InvalidOperationException);
            Assert.False(result);

            sut = new SignatureService().WithPkcs1();

            (success, result, error) = sut.VerifyHash(_hash, _signature);

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

            var (success, result, error) = sut.VerifyHash(default, _signature);

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

            var (success, result, error) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }

        [Fact]
        public void VerifyHashWithNullSignatureFails()
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var sut = Create(publicKey, privateKey);

            var (success, result, error) = sut.VerifyHash(_hash, default);

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

            var (success, result, error) = sut.VerifyHash(_hash, _signature);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.False(result);
        }
        #endregion

        #region Roundtrip works
        #region Payload
        [Property]
        public Property RoundtripForSigningDataWorks(NonEmptyString data)
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var payload = new Payload(Encoding.UTF8.GetBytes(data.Get));
            var sut = new SignatureService().WithSHA512().WithSigningKey(privateKey).WithPkcs1();

            var (signOk, signature, signError) =
                sut.SignPayload(payload);

            sut.WithVerificationKey(publicKey);

            var (verifyOk, result, verifyError) =
                sut.VerifyPayload(payload, signature);

            return (signOk && signError is null && !(signature is null) &&
                verifyOk && verifyError is null && result).ToProperty();
        }
        #endregion

        #region Hash
        [Property]
        public Property RoundtripForSigningHashWorks(NonEmptyString data)
        {
            var (publicKey, privateKey) = CreateKeyPair();
            var payload = new SFX.Crypto.CSharp.Model.Hashing.Payload(Encoding.UTF8.GetBytes(data.Get));
            var hashService =
                new HashService().WithSHA512CryptoServiceProvider();
            var hash_ = hashService.ComputeHash(payload);
            var hash = new SFX.Crypto.CSharp.Model.Signature.Hash(hash_.Value.Value);
            var sut = new SignatureService().WithSHA512().WithSigningKey(privateKey).WithPkcs1();

            var (signOk, signature, signError) =
                sut.SignHash(hash);

            sut.WithVerificationKey(publicKey);

            var (verifyOk, result, verifyError) =
                sut.VerifyHash(hash, signature);

            return (signOk && signError is null && !(signature is null) &&
                verifyOk && verifyError is null && result).ToProperty();
        }
        #endregion
        #endregion

        #region Helpers
        private SignatureService Create(IVerificationKey verificationKey, ISigningKey signingKey) =>
            new SignatureService()
            .WithSHA512()
            .WithPkcs1()
            .WithVerificationKey(verificationKey)
            .WithSigningKey(signingKey);

        private (VerificationKey Verification, SigningKey Signing) CreateKeyPair() =>
            _keyProvider.GenerateKeyPair();
        #endregion
    }
}
