using SFX.Crypto.CSharp.Model.Hash.SHA512;
using SFX.ROP.CSharp;
using System;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Hash.SHA512
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
        Result<IHash> ComputeHash(IUnhashedPayload payload);
    }

    /// <summary>
    /// Implements <see cref="IHashService"/>
    /// </summary>
    public sealed class HashService : IHashService
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="hashAlgorithmProvider">The <see cref="IHashAlgorithmProvider"/> utilized</param>
        public HashService(IHashAlgorithmProvider hashAlgorithmProvider) =>
            HashAlgorithmProvider = hashAlgorithmProvider ?? throw new ArgumentNullException(nameof(hashAlgorithmProvider));

        internal IHashAlgorithmProvider HashAlgorithmProvider { get; }

        /// <inheritdoc/>
        public Result<IHash> ComputeHash(IUnhashedPayload payload)
        {
            if (payload is null)
                return Fail<IHash>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IHash>(new ArgumentException(nameof(payload)));

            IHashAlgorithm algorithm = default;
            try
            {
                var algOk = true;
                Exception algError = default;
                (algOk, algError, algorithm) = HashAlgorithmProvider.GetHashAlgorithm();
                if (!algOk)
                    return Fail<IHash>(algError);
                var result = algorithm.ComputeHash(payload.Value);
                return Succeed(new Model.Hash.SHA512.Hash(result) as IHash);
            }
            catch (Exception error)
            {
                return Fail<IHash>(error);
            }
            finally
            {
                algorithm?.Dispose();
            }
        }
    }
}
