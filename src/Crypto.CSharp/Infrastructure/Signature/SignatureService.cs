using SFX.Crypto.CSharp.Model.Signature;
using SFX.ROP.CSharp;
using System;
using System.Linq;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Signature
{
    /// <summary>
    /// Abstract implementation of <see cref="ISignatureService"/>
    /// </summary>
    public sealed class SignatureService : ISignatureService
    {
        internal ISigningKey SigningKey { get; private set; }
        internal IVerificationKey VerificationKey { get; private set; }

        /// <inheritdoc/>
        public Result<ISignature> SignPayload(IPayload payload)
        {
            if (!IsServiceSetUp())
                return Fail<ISignature>(new InvalidOperationException("Service not properly set up. Hash algorithm and padding must be set"));
            if (payload is null)
                return Fail<ISignature>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<ISignature>(new ArgumentException(nameof(payload)));

            RSACryptoServiceProvider rsa = default;
            try
            {
                rsa = new RSACryptoServiceProvider();
                rsa.ImportRSAPublicKey(SigningKey.Value, out var _);
                rsa.ImportRSAPrivateKey(VerificationKey.Value, out var _);
                var result = rsa.SignData(payload.Value, Algorithm, Padding);
                return Succeed(new Model.Signature.Signature(result) as ISignature);
            }
            catch (Exception error)
            {
                return Fail<ISignature>(error);
            }
            finally
            {
                rsa?.Dispose();
            }
        }

        /// <inheritdoc/>
        public Result<ISignature> SignHash(IHash hash)
        {
            if (!IsServiceSetUp())
                return Fail<ISignature>(new InvalidOperationException("Service not properly set up. Hash algorithm and padding must be set"));
            if (hash is null)
                return Fail<ISignature>(new ArgumentNullException(nameof(hash)));
            if (!hash.IsValid())
                return Fail<ISignature>(new ArgumentException(nameof(hash)));

            RSACryptoServiceProvider rsa = default;
            try
            {
                rsa = new RSACryptoServiceProvider();
                rsa.ImportRSAPublicKey(SigningKey.Value, out var _);
                rsa.ImportRSAPrivateKey(VerificationKey.Value, out var _);
                var result = rsa.SignHash(hash.Value, Algorithm, Padding);
                return Succeed(new Model.Signature.Signature(result) as ISignature);
            }
            catch (Exception error)
            {
                return Fail<ISignature>(error);
            }
            finally
            {
                rsa?.Dispose();
            }
        }

        /// <inheritdoc/>
        public Result<bool> VerifyPayload(IPayload payload, ISignature signature)
        {
            if (!IsServiceSetUp())
                return Fail<bool>(new InvalidOperationException("Service not properly set up. Hash algorithm and padding must be set"));
            if (payload is null)
                return Fail<bool>(new ArgumentNullException(nameof(signature)));
            if (!payload.IsValid())
                return Fail<bool>(new ArgumentException(nameof(signature)));
            if (signature is null)
                return Fail<bool>(new ArgumentNullException(nameof(signature)));
            if (!signature.IsValid())
                return Fail<bool>(new ArgumentException(nameof(signature)));

            RSACryptoServiceProvider rsa = default;
            try
            {
                rsa = new RSACryptoServiceProvider();
                rsa.ImportRSAPublicKey(SigningKey.Value, out var _);
                rsa.ImportRSAPrivateKey(VerificationKey.Value, out var _);
                var result = rsa.VerifyData(payload.Value, signature.Value, Algorithm, Padding);
                return Succeed(result);
            }
            catch (Exception error)
            {
                return Fail<bool>(error);
            }
            finally
            {
                rsa?.Dispose();
            }
        }

        /// <inheritdoc/>
        public Result<bool> VerifyHash(IHash hash, ISignature signature)
        {
            if (!IsServiceSetUp())
                return Fail<bool>(new InvalidOperationException("Service not properly set up. Hash algorithm and padding must be set"));
            if (hash is null)
                return Fail<bool>(new ArgumentNullException(nameof(signature)));
            if (!hash.IsValid())
                return Fail<bool>(new ArgumentException(nameof(signature)));
            if (signature is null)
                return Fail<bool>(new ArgumentNullException(nameof(signature)));
            if (!signature.IsValid())
                return Fail<bool>(new ArgumentException(nameof(signature)));

            RSACryptoServiceProvider rsa = default;
            try
            {
                rsa = new RSACryptoServiceProvider();
                rsa.ImportRSAPublicKey(SigningKey.Value, out var _);
                rsa.ImportRSAPrivateKey(VerificationKey.Value, out var _);
                var result = rsa.VerifyHash(hash.Value, signature.Value, Algorithm, Padding);
                return Succeed(result);
            }
            catch (Exception error)
            {
                return Fail<bool>(error);
            }
            finally
            {
                rsa?.Dispose();
            }
        }

        private bool IsServiceSetUp() =>
            IsValidAlgoritmSet &&
            IsValidPaddingSet &&
            !(SigningKey is null) &&
            SigningKey.IsValid() &&
            !(VerificationKey is null) &&
            VerificationKey.IsValid();

        internal bool IsValidAlgoritmSet;
        internal HashAlgorithmName Algorithm;

        private static HashAlgorithmName[] ValidAlgorithms = new[]
        {
            HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512, HashAlgorithmName.MD5
        };
        private static bool IsValidAlgorithm(HashAlgorithmName name) =>
            ValidAlgorithms.Contains(name);
        private SignatureService WithAlgorithm(HashAlgorithmName name)
        {
            Algorithm = name;
            IsValidAlgoritmSet = IsValidAlgorithm(name);
            return this;
        }
        public SignatureService WithSHA1() => WithAlgorithm(HashAlgorithmName.SHA1);
        public SignatureService WithSHA256() => WithAlgorithm(HashAlgorithmName.SHA256);
        public SignatureService WithSHA384() => WithAlgorithm(HashAlgorithmName.SHA384);
        public SignatureService WithSHA512() => WithAlgorithm(HashAlgorithmName.SHA512);
        public SignatureService WithMD5() => WithAlgorithm(HashAlgorithmName.MD5);

        internal bool IsValidPaddingSet;
        internal RSASignaturePadding Padding;

        private static RSASignaturePadding[] ValidPaddings = new[]
        {
            RSASignaturePadding.Pkcs1, RSASignaturePadding.Pss
        };
        private static bool IsValidPadding(RSASignaturePadding padding) =>
            !(padding is null) && ValidPaddings.Contains(padding);
        private SignatureService WithPadding(RSASignaturePadding padding)
        {
            Padding = padding;
            IsValidPaddingSet = IsValidPadding(padding);
            return this;
        }
        public SignatureService WithPkcs1() =>
            WithPadding(RSASignaturePadding.Pkcs1);
        public SignatureService WithPss() =>
            WithPadding(RSASignaturePadding.Pss);

        public SignatureService WithSigningKey(ISigningKey signingKey)
        {
            SigningKey = signingKey;
            return this;
        }

        public SignatureService WithVerificationKey(IVerificationKey verificationKey)
        {
            VerificationKey = verificationKey;
            return this;
        }
    }


}
