using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Interface providing the actual utilized Aes algorithm
    /// </summary>
    public interface IAesProvider
    {
        /// <summary>
        /// Provides an instance of the Aes algorithm
        /// </summary>
        /// <returns></returns>
        Result<System.Security.Cryptography.Aes> GetAlgorithm();
    }
}
