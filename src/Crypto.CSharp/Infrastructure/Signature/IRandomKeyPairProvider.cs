using SFX.Crypto.CSharp.Model.Signature;
using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Signature
{
    /// <summary>
    /// Interface describing the capability to generate private and public keys
    /// </summary>
    public interface IRandomKeyPairProvider
    {
        /// <summary>
        /// Generates a random key pair for RSA signing and verification
        /// </summary>
        /// <returns></returns>
        Result<(ISigningKey SigningKey, IVerificationKey VerificationKey)> GenerateKeyPair();
    }
}
