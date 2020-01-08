using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Rijndael;
using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Rijndael
{
    /// <summary>
    /// Interface describing the capability to generate secret and salt
    /// </summary>
    public interface IRandomSecretAndSaltProvider
    {
        /// <summary>
        /// Generates a random key pair for Aes encryption and decryption
        /// </summary>
        /// <returns></returns>
        Result<(ISecret Secret, ISalt Salt)> GenerateKeyPair();

        /// <summary>
        /// Initializes the provider to use the provided <paramref name="algorithm"/>
        /// </summary>
        /// <param name="algorithm">The algorithm to use</param>
        /// <returns>The current instance</returns>
        IRandomSecretAndSaltProvider WithAlgorithm(System.Security.Cryptography.Aes algorithm);
    }
}
