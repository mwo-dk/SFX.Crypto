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

        /// <inheritdoc/>
        public IHashService WithAlgorithm(HashAlgorithm algorithm)
        {
            if (IsDisposed())
                throw new ObjectDisposedException(typeof(HashService).Name);
            if (!(Algorithm is null) && !ReferenceEquals(Algorithm, algorithm))
                Algorithm.Dispose();

            Algorithm = algorithm;
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

    public static class HashServiceExtensions
    {
        public static IHashService WithSHA1CryptoServiceProvider(this IHashService service) =>
            service?.WithAlgorithm(new SHA1CryptoServiceProvider());
        public static IHashService WithSHA1Managed(this IHashService service) =>
            service?.WithAlgorithm(new SHA1Managed());
        public static IHashService WithSHA256CryptoServiceProvider(this IHashService service) =>
            service?.WithAlgorithm(new SHA256CryptoServiceProvider());
        public static IHashService WithSHA256Managed(this IHashService service) =>
            service?.WithAlgorithm(new SHA256Managed());
        public static IHashService WithSHA384CryptoServiceProvider(this IHashService service) =>
            service?.WithAlgorithm(new SHA384CryptoServiceProvider());
        public static IHashService WithSHA384Managed(this IHashService service) =>
            service?.WithAlgorithm(new SHA384Managed());
        public static IHashService WithSHA512CryptoServiceProvider(this IHashService service) =>
            service?.WithAlgorithm(new SHA512CryptoServiceProvider());
        public static IHashService WithSHA512Managed(this IHashService service) =>
            service?.WithAlgorithm(new SHA512Managed());
        public static IHashService WithMD5CryptoServiceProvider(this IHashService service) =>
            service?.WithAlgorithm(new MD5CryptoServiceProvider());
    }
}
