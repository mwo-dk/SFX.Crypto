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
        public Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload, IEncryptionKey key)
        {
            if (IsDisposed())
                return Fail<IEncryptedPayload>(new ObjectDisposedException(typeof(CryptoService).Name));
            if (Algorithm is null)
                return Fail<IEncryptedPayload>(new InvalidOperationException("CryptoService is not initialized"));
            if (payload is null)
                return Fail<IEncryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IEncryptedPayload>(new ArgumentException(nameof(payload)));
            if (key is null)
                return Fail<IEncryptedPayload>(new ArgumentNullException(nameof(key)));
            if (!key.IsValid())
                return Fail<IEncryptedPayload>(new ArgumentException(nameof(key)));

            try
            {
                Algorithm.ImportRSAPublicKey(key.Value, out var _);
                var result = Algorithm.Encrypt(payload.Value, RSAEncryptionPadding.Pkcs1);
                return Succeed(new EncryptedPayload(result) as IEncryptedPayload);
            }
            catch (Exception error)
            {
                return Fail<IEncryptedPayload>(error);
            }
        }

        /// <inheritdoc/>
        public Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload, IDecryptionKey key)
        {
            if (IsDisposed())
                return Fail<IUnencryptedPayload>(new ObjectDisposedException(typeof(CryptoService).Name));
            if (Algorithm is null)
                return Fail<IUnencryptedPayload>(new InvalidOperationException("CryptoService is not initialized"));
            if (payload is null)
                return Fail<IUnencryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IUnencryptedPayload>(new ArgumentException(nameof(payload)));
            if (key is null)
                return Fail<IUnencryptedPayload>(new ArgumentNullException(nameof(key)));
            if (!key.IsValid())
                return Fail<IUnencryptedPayload>(new ArgumentException(nameof(key)));

            try
            {
                Algorithm.ImportRSAPrivateKey(key.Value, out var _);
                var result = Algorithm.Decrypt(payload.Value, RSAEncryptionPadding.Pkcs1);
                return Succeed(new UnencryptedPayload(result) as IUnencryptedPayload);
            }
            catch (Exception error)
            {
                return Fail<IUnencryptedPayload>(error);
            }
        }

        private System.Security.Cryptography.RSA Algorithm;

        internal CryptoService WithAlgorihm(System.Security.Cryptography.RSA algorithm)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(CryptoService).Name);

            if (!(Algorithm is null) && !ReferenceEquals(Algorithm, algorithm))
                Algorithm.Dispose();

            Algorithm = algorithm;
            return this;
        }
        public CryptoService WithRSACryptoServiceProvider() =>
            WithAlgorihm(new RSACryptoServiceProvider());

        internal long DisposeCount;
        private bool IsDisposed() => 0L < Read(ref DisposeCount);
        public void Dispose()
        {
            if (1L < Increment(ref DisposeCount))
                return;

            Algorithm?.Dispose();
        }
    }
}
