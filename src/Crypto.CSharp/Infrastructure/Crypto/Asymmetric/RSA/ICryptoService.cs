using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Interface describing the capability to encrypt and unencrypt data based on
    /// provided keys
    /// </summary>
    public interface ICryptoService
    {
        /// <summary>
        /// Encrypts the provided <paramref name="payload"/> based on the provided <paramref name="key"/>
        /// </summary>
        /// <param name="payload">The <see cref="IUnencryptedPayload"/> to encrypt</param>
        /// <param name="key">The <see cref="IEncryptionKey"/> utilized</param>
        /// <returns><paramref name="payload"/> encrypted</returns>
        Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload, IEncryptionKey key);

        /// <summary>
        /// Decrypts the provided <paramref name="payload"/> based on the provided <paramref name="key"/>
        /// </summary>
        /// <param name="payload">The <see cref="IEncryptedPayload"/> to decrypt</param>
        /// <param name="key">The <see cref="IDecryptionSecret"/> to utilize</param>
        /// <returns><paramref name="payload"/> decrypted</returns>
        Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload, IDecryptionKey key);
    }
}
