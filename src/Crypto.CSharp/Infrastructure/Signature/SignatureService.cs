using SFX.Crypto.CSharp.Model.Signature;
using SFX.ROP.CSharp;
using System;
using System.Linq;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;
using static System.Threading.Interlocked;

namespace SFX.Crypto.CSharp.Infrastructure.Signature
{
    /// <summary>
    /// Abstract implementation of <see cref="ISignatureService"/>
    /// </summary>
    public sealed class SignatureService : ISignatureService, IDisposable
    {
        /// <inheritdoc/>
        public Result<ISignature> SignPayload(IPayload payload)
        {
            if (IsDisposed())
                return Fail<ISignature>(new ObjectDisposedException(typeof(SignatureService).Name));
            if (!IsServiceSetUp())
                return Fail<ISignature>(new InvalidOperationException("Service not properly set up. Hash algorithm and padding must be set"));
            if (payload is null)
                return Fail<ISignature>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<ISignature>(new ArgumentException(nameof(payload)));

            try
            {
                var result = Algorithm.SignData(payload.Value, HashAlgorithm, Padding);
                return Succeed(new Model.Signature.Signature(result) as ISignature);
            }
            catch (Exception error)
            {
                return Fail<ISignature>(error);
            }
        }

        /// <inheritdoc/>
        public Result<ISignature> SignHash(IHash hash)
        {
            if (IsDisposed())
                return Fail<ISignature>(new ObjectDisposedException(typeof(SignatureService).Name));
            if (!IsServiceSetUp())
                return Fail<ISignature>(new InvalidOperationException("Service not properly set up. Hash algorithm and padding must be set"));
            if (hash is null)
                return Fail<ISignature>(new ArgumentNullException(nameof(hash)));
            if (!hash.IsValid())
                return Fail<ISignature>(new ArgumentException(nameof(hash)));

            try
            {
                var result = Algorithm.SignHash(hash.Value, HashAlgorithm, Padding);
                return Succeed(new Model.Signature.Signature(result) as ISignature);
            }
            catch (Exception error)
            {
                return Fail<ISignature>(error);
            }
        }

        /// <inheritdoc/>
        public Result<bool> VerifyPayload(IPayload payload, ISignature signature)
        {
            if (IsDisposed())
                return Fail<bool>(new ObjectDisposedException(typeof(SignatureService).Name));
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

            try
            {
                var result = Algorithm.VerifyData(payload.Value, signature.Value, HashAlgorithm, Padding);
                return Succeed(result);
            }
            catch (Exception error)
            {
                return Fail<bool>(error);
            }
        }

        /// <inheritdoc/>
        public Result<bool> VerifyHash(IHash hash, ISignature signature)
        {
            if (IsDisposed())
                return Fail<bool>(new ObjectDisposedException(typeof(SignatureService).Name));
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

            try
            {
                var result = Algorithm.VerifyHash(hash.Value, signature.Value, HashAlgorithm, Padding);
                return Succeed(result);
            }
            catch (Exception error)
            {
                return Fail<bool>(error);
            }
        }

        private bool IsServiceSetUp() =>
            IsValidHashAlgoritmSet &&
            IsValidPaddingSet &&
            IsValidSigningKeySet &&
            IsValidVerificationKeySet;

        internal RSACryptoServiceProvider Algorithm =
            new RSACryptoServiceProvider();

        internal bool IsValidHashAlgoritmSet;
        internal HashAlgorithmName HashAlgorithm;

        private static HashAlgorithmName[] ValidAlgorithms = new[]
        {
            HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512, HashAlgorithmName.MD5
        };
        private static bool IsValidAlgorithm(HashAlgorithmName name) =>
            ValidAlgorithms.Contains(name);
        private SignatureService WithHashAlgorithm(HashAlgorithmName name)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(SignatureService).Name);
            HashAlgorithm = name;
            IsValidHashAlgoritmSet = IsValidAlgorithm(name);
            return this;
        }
        public SignatureService WithSHA1() => WithHashAlgorithm(HashAlgorithmName.SHA1);
        public SignatureService WithSHA256() => WithHashAlgorithm(HashAlgorithmName.SHA256);
        public SignatureService WithSHA384() => WithHashAlgorithm(HashAlgorithmName.SHA384);
        public SignatureService WithSHA512() => WithHashAlgorithm(HashAlgorithmName.SHA512);
        public SignatureService WithMD5() => WithHashAlgorithm(HashAlgorithmName.MD5);

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
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(SignatureService).Name);
            Padding = padding;
            IsValidPaddingSet = IsValidPadding(padding);
            return this;
        }
        public SignatureService WithPkcs1() =>
            WithPadding(RSASignaturePadding.Pkcs1);
        public SignatureService WithPss() =>
            WithPadding(RSASignaturePadding.Pss);

        internal bool IsValidSigningKeySet;
        public SignatureService WithSigningKey(ISigningKey signingKey)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(SignatureService).Name);
            if (signingKey is null)
                throw new ArgumentNullException(nameof(signingKey));
            if (!signingKey.IsValid())
                throw new ArgumentException("Signing key is not valid");
            Algorithm.ImportRSAPublicKey(signingKey.Value, out var _);
            IsValidSigningKeySet = true;
            return this;
        }

        internal bool IsValidVerificationKeySet;
        public SignatureService WithVerificationKey(IVerificationKey verificationKey)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(SignatureService).Name);
            if (verificationKey is null)
                throw new ArgumentNullException(nameof(verificationKey));
            if (!verificationKey.IsValid())
                throw new ArgumentException("Verification key is not valid");
            Algorithm.ImportRSAPrivateKey(verificationKey.Value, out var _);
            IsValidVerificationKeySet = true;
            return this;
        }

        internal long DisposeCount;
        private bool IsDisposed() => 0L < Read(ref DisposeCount);
        public void Dispose()
        {
            if (1L < Increment(ref DisposeCount))
                return;

            Algorithm.Dispose();
        }
    }
}
