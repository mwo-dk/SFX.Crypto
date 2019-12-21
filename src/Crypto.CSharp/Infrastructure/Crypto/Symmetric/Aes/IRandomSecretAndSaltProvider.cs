using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes;
using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
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
    }
}
