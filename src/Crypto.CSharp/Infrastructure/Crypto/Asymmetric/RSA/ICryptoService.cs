﻿using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
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
        /// <returns><paramref name="payload"/> encrypted</returns>
        Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload);

        /// <summary>
        /// Decrypts the provided <paramref name="payload"/> based on the provided <paramref name="key"/>
        /// </summary>
        /// <param name="payload">The <see cref="IEncryptedPayload"/> to decrypt</param>
        /// <returns><paramref name="payload"/> decrypted</returns>
        Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload);

        /// <summary>
        /// Initializes the service to use the provided <paramref name="algorithm"/>
        /// </summary>
        /// <param name="algorithm">The algorithm to use</param>
        /// <returns>The current instance</returns>
        ICryptoService WithAlgorihm(System.Security.Cryptography.RSA algorithm);

        /// <summary>
        /// Instruments the service to use the provided <paramref name="key"/> for encryption
        /// </summary>
        /// <param name="key">The key utilized for encryption</param>
        /// <returns>The current instance</returns>
        ICryptoService WithEncryptionKey(IEncryptionKey key);

        /// <summary>
        /// Instruments the service to use the provided <paramref name="key"/> for decryption
        /// </summary>
        /// <param name="key">The key utilized for decryption</param>
        /// <returns>The current instance</returns>
        ICryptoService WithDeryptionKey(IDecryptionKey key);
    }
}
