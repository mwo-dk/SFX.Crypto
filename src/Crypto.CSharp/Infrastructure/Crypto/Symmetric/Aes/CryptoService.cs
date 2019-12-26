using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes;
using SFX.ROP.CSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using static SFX.ROP.CSharp.Library;
using static System.Threading.Interlocked;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Implements <see cref="ICryptoService"/>
    /// </summary>
    public sealed class CryptoService : ICryptoService, IDisposable
    {
        /// <inheritdoc/>
        public Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload)
        {
            if (IsDisposed())
                return Fail<IEncryptedPayload>(new ObjectDisposedException(typeof(CryptoService).Name));
            if (Algorithm is null)
                return Fail<IEncryptedPayload>(new InvalidOperationException("CryptoService is not initialized"));
            if (payload is null)
                return Fail<IEncryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IEncryptedPayload>(new ArgumentException(nameof(payload)));

            try
            {
                using var encryptor = Algorithm.CreateEncryptor();
                using var ms = new MemoryStream();
                using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
                using var writer = new BinaryWriter(cs);
                writer.Write(payload.Value);
                cs.FlushFinalBlock();
                var result = ms.ToArray();
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
            if (Algorithm is null)
                return Fail<IUnencryptedPayload>(new InvalidOperationException("CryptoService is not initialized"));
            if (payload is null)
                return Fail<IUnencryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IUnencryptedPayload>(new ArgumentException(nameof(payload)));

            try
            {
                using var encryptor = Algorithm.CreateDecryptor();
                using var ms = new MemoryStream(payload.Value);
                using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Read);
                using var reader = new BinaryReader(cs);
                var result = new List<byte>();
                var bufferSize = 1024;
                byte[] buffer = new byte[bufferSize];
                bool ReadData()
                {
                    var read = reader.Read(buffer, 0, bufferSize);
                    if (read > 0)
                        result.AddRange(buffer.Take(read));
                    return 0 == read;
                }
                while (ReadData()) ;
                return Succeed(new UnencryptedPayload(result.ToArray()) as IUnencryptedPayload);
            }
            catch (Exception error)
            {
                return Fail<IUnencryptedPayload>(error);
            }
        }

        private System.Security.Cryptography.Aes Algorithm;

        internal CryptoService WithAlgorihm(System.Security.Cryptography.Aes algorithm)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(CryptoService).Name);

            if (!(Algorithm is null) && !ReferenceEquals(Algorithm, algorithm))
                Algorithm.Dispose();

            Algorithm = algorithm;
            Algorithm.Padding = PaddingMode.PKCS7;
            Algorithm.Mode = CipherMode.CBC;
            return this;
        }
        public CryptoService WithAesCryptoServiceProvider() =>
            WithAlgorihm(new AesCryptoServiceProvider());
        public CryptoService WithAesManaged() =>
            WithAlgorihm(new AesManaged());

        internal bool IsSecretSet;
        public CryptoService WithSecret(ISecret secret)
        {
            if (Algorithm is null)
                throw new InvalidOperationException("Unable to set up secret. Algorithm must be denoted first");
            if (secret is null)
                throw new ArgumentNullException(nameof(secret));
            Algorithm.Key = secret.Value;
            IsSecretSet = true;
            return this;
        }

        internal bool IsDecryptionKeySet;
        public CryptoService WithSalt(ISalt salt)
        {
            if (Algorithm is null)
                throw new InvalidOperationException("Unable to set up salt. Algorithm must be denoted first");
            if (salt is null)
                throw new ArgumentNullException(nameof(salt));
            Algorithm.IV = salt.Value;
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
}
