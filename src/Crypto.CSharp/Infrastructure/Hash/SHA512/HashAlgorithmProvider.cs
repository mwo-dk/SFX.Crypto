using SFX.ROP.CSharp;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Hash.SHA512
{
    // <summary>
    /// Interface describing the capability of serving a <see cref="IHashAlgorithm"/>
    /// </summary>
    public interface IHashAlgorithmProvider
    {
        /// <summary>
        /// Serves a <see cref=IHashAlgorithm"/>
        /// </summary>
        /// <returns></returns>
        Result<IHashAlgorithm> GetHashAlgorithm();
    }

    /// <summary>
    /// Implements <see cref="IHashAlgorithmProvider"/>
    /// </summary>
    public sealed class HashAlgorithmProvider : IHashAlgorithmProvider
    {
        public Result<IHashAlgorithm> GetHashAlgorithm()
        {
            var result = new HashAlgorithm();
            result.Initialize();
            return Succeed<IHashAlgorithm>(result as IHashAlgorithm);
        }
    }
}