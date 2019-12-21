using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Interface providing the actual utilized RSA algorithm
    /// </summary>
    public interface IRSAProvider
    {
        /// <summary>
        /// Provides an instance of the RSA algorithm
        /// </summary>
        /// <returns></returns>
        Result<System.Security.Cryptography.RSA> GetAlgorithm();
    }
}
