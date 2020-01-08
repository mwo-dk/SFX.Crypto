using SFX.Crypto.CSharp.Model.Hashing;
using SFX.ROP.CSharp;
using System.Security.Cryptography;

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

        /// <summary>
        /// Initializes the service to use the provided <paramref name="algorithm"/>
        /// </summary>
        /// <param name="algorithm">The algorithm to use</param>
        /// <returns>The current instance</returns>
        IHashService WithAlgorithm(HashAlgorithm algorithm);
    }
}
