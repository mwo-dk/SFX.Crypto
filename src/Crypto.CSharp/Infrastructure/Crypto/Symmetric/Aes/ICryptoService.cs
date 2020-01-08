using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes;
using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Interface describing the capability to encrypt and unencrypt data based on
    /// provided keys
    /// </summary>
    public interface ICryptoService
    {
        /// <summary>
        /// Encrypts the provided <paramref name="payload"/> based on the provided <paramref name="secret"/> and <paramref name="salt"/>
        /// </summary>
        /// <param name="payload">The <see cref="IUnencryptedPayload"/> to encrypt</param>
        /// <returns><paramref name="payload"/> encrypted</returns>
        Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload);

        /// <summary>
        /// Decrypts the provided <paramref name="payload"/> based on the provided <paramref name="secret"/> and <paramref name="salt"/>
        /// </summary>
        /// <param name="payload">The <see cref="IEncryptedPayload"/> to decrypt</param>
        /// <returns><paramref name="payload"/> decrypted</returns>
        Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload);

        /// <summary>
        /// Initializes the service to use the provided <paramref name="algorithm"/>
        /// </summary>
        /// <param name="algorithm">The algorithm to use</param>
        /// <returns>The current instance</returns>
        ICryptoService WithAlgorihm(System.Security.Cryptography.Aes algorithm);

        /// <summary>
        /// Instruments the service to utilize the provided <paramref name="secret"/>
        /// </summary>
        /// <param name="secret">The secret to utilize</param>
        /// <returns>The current instance</returns>
        ICryptoService WithSecret(ISecret secret);

        /// <summary>
        /// Instruments the service to utilize the provided <paramref name="secret"/>
        /// </summary>
        /// <param name="secret">The secret to utilize</param>
        /// <returns>The current instance</returns>
        ICryptoService WithSalt(ISalt salt);
    }
}
