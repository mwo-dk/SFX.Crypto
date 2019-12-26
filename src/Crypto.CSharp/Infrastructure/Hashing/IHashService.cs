using SFX.Crypto.CSharp.Model.Hashing;
using SFX.ROP.CSharp;

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
}
