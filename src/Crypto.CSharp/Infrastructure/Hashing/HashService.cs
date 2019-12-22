using SFX.Crypto.CSharp.Model.Hashing;
using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;
using static System.Threading.Interlocked;

namespace SFX.Crypto.CSharp.Infrastructure.Hashing
{
    /// <summary>
    /// Interface describing the capability of hashing
    /// </summary>
    public interface IHashService
    {
        /// <summary>
        /// Computes the hash <paramref name="payload"/>
        /// </summary>
        /// <param name="payload">The payload to hash</param>
        /// <returns><paramref name="payload"/> hashed</returns>
        Result<IHash> ComputeHash(IPayload payload);
    }

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

        private HashService WithAlgorithm(HashAlgorithm algorithm)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(HashService).Name);

            if (!(Algorithm is null) && !ReferenceEquals(Algorithm, algorithm))
                Algorithm.Dispose();

            Algorithm = algorithm;
            return this;
        }
        public HashService WithSHA1() => WithAlgorithm(SHA1.Create());
        public HashService WithSHA256() => WithAlgorithm(SHA256.Create());
        public HashService WithSHA384() => WithAlgorithm(SHA384.Create());
        public HashService WithSHA512() => WithAlgorithm(SHA512.Create());
        public HashService WithMD5() => WithAlgorithm(MD5.Create());

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
