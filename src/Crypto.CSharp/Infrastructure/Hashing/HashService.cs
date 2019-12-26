using SFX.Crypto.CSharp.Model.Hashing;
using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;
using static System.Threading.Interlocked;

namespace SFX.Crypto.CSharp.Infrastructure.Hashing
{
    /// <summary>
    /// Implements <see cref="IHashService"/>
    /// </summary>
    public sealed class HashService : IHashService, IDisposable
    {
        /// <inheritdoc/>
        public Result<IHash> ComputeHash(IPayload payload)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(HashService).Name);

            if (Algorithm is null)
                return Fail<IHash>(new InvalidOperationException($"Hashing algorithm is not set"));
            if (payload is null)
                return Fail<IHash>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IHash>(new ArgumentException(nameof(payload)));

            try
            {
                var result = Algorithm.ComputeHash(payload.Value);
                return Succeed(new Hash(result) as IHash);
            }
            catch (Exception error)
            {
                return Fail<IHash>(error);
            }
        }

        private HashAlgorithm Algorithm;

        internal HashService WithAlgorithm(HashAlgorithm algorithm)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(HashService).Name);
            if (!(Algorithm is null) && !ReferenceEquals(Algorithm, algorithm))
                Algorithm.Dispose();

            Algorithm = algorithm;
            return this;
        }
        public HashService WithSHA1CryptoServiceProvider() =>
            WithAlgorithm(new SHA1CryptoServiceProvider());
        public HashService WithSHA1Managed() =>
            WithAlgorithm(new SHA1Managed());
        public HashService WithSHA256CryptoServiceProvider() =>
            WithAlgorithm(new SHA256CryptoServiceProvider());
        public HashService WithSHA256Managed() =>
            WithAlgorithm(new SHA256Managed());
        public HashService WithSHA384CryptoServiceProvider() =>
            WithAlgorithm(new SHA384CryptoServiceProvider());
        public HashService WithSHA384Managed() =>
            WithAlgorithm(new SHA384Managed());
        public HashService WithSHA512CryptoServiceProvider() =>
            WithAlgorithm(new SHA512CryptoServiceProvider());
        public HashService WithSHA512Managed() =>
            WithAlgorithm(new SHA512Managed());
        public HashService WithMD5CryptoServiceProvider() =>
            WithAlgorithm(new MD5CryptoServiceProvider());

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
