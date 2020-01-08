using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;
using static System.Threading.Interlocked;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Implements <see cref="ICryptoService"/> utilizing RSA
    /// </summary>
    public sealed class CryptoService : ICryptoService, IDisposable
    {
        /// <inheritdoc/>
        public Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload)
        {
            if (IsDisposed())
                return Fail<IEncryptedPayload>(new ObjectDisposedException(typeof(CryptoService).Name));
            if (Algorithm is null || !IsEncryptionKeySet)
                return Fail<IEncryptedPayload>(new InvalidOperationException("CryptoService is not initialized"));
            if (payload is null)
                return Fail<IEncryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IEncryptedPayload>(new ArgumentException(nameof(payload)));

            try
            {
                var result = Algorithm.Encrypt(payload.Value, RSAEncryptionPadding.Pkcs1);
                return Succeed(new EncryptedPayload(result) as IEncryptedPayload);
            }
            catch (Exception error)
            {
                return Fail<IEncryptedPayload>(error);
            }
        }

        /// <inheritdoc/>
        public Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload)
        {
            if (IsDisposed())
                return Fail<IUnencryptedPayload>(new ObjectDisposedException(typeof(CryptoService).Name));
            if (Algorithm is null || !IsDecryptionKeySet)
                return Fail<IUnencryptedPayload>(new InvalidOperationException("CryptoService is not initialized"));
            if (payload is null)
                return Fail<IUnencryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IUnencryptedPayload>(new ArgumentException(nameof(payload)));

            try
            {
                var result = Algorithm.Decrypt(payload.Value, RSAEncryptionPadding.Pkcs1);
                return Succeed(new UnencryptedPayload(result) as IUnencryptedPayload);
            }
            catch (Exception error)
            {
                return Fail<IUnencryptedPayload>(error);
            }
        }

        private System.Security.Cryptography.RSA Algorithm;
        /// <inheritdoc/>
        public ICryptoService WithAlgorihm(System.Security.Cryptography.RSA algorithm)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(CryptoService).Name);

            if (!(Algorithm is null) && !ReferenceEquals(Algorithm, algorithm))
                Algorithm.Dispose();

            Algorithm = algorithm;
            return this;
        }

        internal bool IsEncryptionKeySet;
        /// <inheritdoc/>
        public ICryptoService WithEncryptionKey(IEncryptionKey key)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(CryptoService).Name);
            if (Algorithm is null)
                throw new InvalidOperationException("Unable to set up encryption key. Algorithm must be denoted first");
            if (key is null)
                throw new ArgumentNullException(nameof(key));
            Algorithm.ImportRSAPublicKey(key.Value, out var _);
            IsEncryptionKeySet = true;
            return this;
        }

        internal bool IsDecryptionKeySet;
        /// <inheritdoc/>
        public ICryptoService WithDeryptionKey(IDecryptionKey key)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(CryptoService).Name);
            if (Algorithm is null)
                throw new InvalidOperationException("Unable to set up decryption key. Algorithm must be denoted first");
            if (key is null)
                throw new ArgumentNullException(nameof(key));
            Algorithm.ImportRSAPrivateKey(key.Value, out var _);
            IsDecryptionKeySet = true;
            return this;
        }

        internal long DisposeCount;
        private bool IsDisposed() => 0L < Read(ref DisposeCount);
        public void Dispose()
        {
            if (1L < Increment(ref DisposeCount))
                return;

            Algorithm?.Dispose();
        }
    }

    public static class CryptoServiceExtensions
    {
        /// <summary>
        /// Instruments <paramref name="service"/> to utilize <see cref="RSACryptoServiceProvider"/>
        /// </summary>
        /// <param name="service"></param>
        /// <returns><paramref name="service"/></returns>
        public static ICryptoService WithRSACryptoServiceProvider(this ICryptoService service) =>
            service?.WithAlgorihm(new RSACryptoServiceProvider());
    }
}
