using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Interface describing the capability to generate private and public keys
    /// </summary>
    /// <typeparam name="PUBLICKEY">The <see cref="Type"/> of the public key</typeparam>
    /// <typeparam name="PRIVATEKEY">The <see cref="Type"/> of the private key</typeparam>
    public interface IRandomKeyPairProvider<PUBLICKEY, PRIVATEKEY>
    {
        /// <summary>
        /// Generates a random key pair for RSA encryption and decryption
        /// </summary>
        /// <returns></returns>
        Result<(PUBLICKEY PublicKey, PRIVATEKEY PrivateKey)> GenerateKeyPair();
    }
}
