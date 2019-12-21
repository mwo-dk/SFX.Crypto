﻿using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes;
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
        /// <param name="secret">The <see cref="ISecret"/> utilized</param>
        /// <param name="salt">The <see cref="ISalt"/> utilized</param>
        /// <returns><paramref name="payload"/> encrypted</returns>
        Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload, ISecret secret, ISalt salt);

        /// <summary>
        /// Decrypts the provided <paramref name="payload"/> based on the provided <paramref name="secret"/> and <paramref name="salt"/>
        /// </summary>
        /// <param name="payload">The <see cref="IEncryptedPayload"/> to decrypt</param>
        /// <param name="secret">The <see cref="ISecret"/> utilized</param>
        /// <param name="salt">The <see cref="ISalt"/> to utilize</param>
        /// <returns><paramref name="payload"/> decrypted</returns>
        Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload, ISecret secret, ISalt salt);
    }
}