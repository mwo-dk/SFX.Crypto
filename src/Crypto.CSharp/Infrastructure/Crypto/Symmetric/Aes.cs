using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes;
using SFX.ROP.CSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

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

    /// <summary>
    /// Implements <see cref="ICryptoService"/>
    /// </summary>
    public abstract class AesCryptoServiceBase : ICryptoService
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="aesProvider">The <see cref="IAesProvider"/> utilized</param>
        public AesCryptoServiceBase(IAesProvider aesProvider) =>
            AesProvider = aesProvider ?? throw new ArgumentNullException(nameof(aesProvider));

        internal IAesProvider AesProvider { get; }

        /// <inheritdoc/>
        public Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload, ISecret secret, ISalt salt)
        {
            if (payload is null)
                return Fail<IEncryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IEncryptedPayload>(new ArgumentException(nameof(payload)));
            if (secret is null)
                return Fail<IEncryptedPayload>(new ArgumentNullException(nameof(secret)));
            if (!secret.IsValid())
                return Fail<IEncryptedPayload>(new ArgumentException(nameof(secret)));
            if (salt is null)
                return Fail<IEncryptedPayload>(new ArgumentNullException(nameof(salt)));
            if (!salt.IsValid())
                return Fail<IEncryptedPayload>(new ArgumentException(nameof(salt)));

            System.Security.Cryptography.Aes algorithm = default;
            try
            {
                var success = false;
                Exception error = default;
                (success, error, algorithm) = AesProvider.GetAlgorithm();
                if (!success)
                    return Fail<IEncryptedPayload>(error);
                if (algorithm is null)
                    return Fail<IEncryptedPayload>(new NullReferenceException("Error fetching algorithm - algorithm provided is null"));

                algorithm.Padding = PaddingMode.PKCS7;
                algorithm.Mode = CipherMode.CBC;
                algorithm.Key = secret.Value;
                algorithm.IV = salt.Value;
                using var encryptor = algorithm.CreateEncryptor();
                using var ms = new MemoryStream();
                using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
                using var writer = new BinaryWriter(cs);
                writer.Write(payload.Value);
                cs.FlushFinalBlock();
                var result = ms.ToArray();
                return Succeed(new EncryptedPayload(result) as IEncryptedPayload);
            }
            catch (Exception error)
            {
                return Fail<IEncryptedPayload>(error);
            }
            finally
            {
                algorithm?.Dispose();
            }
        }

        /// <inheritdoc/>
        public Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload, ISecret secret, ISalt salt)
        {
            if (payload is null)
                return Fail<IUnencryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IUnencryptedPayload>(new ArgumentException(nameof(payload)));
            if (secret is null)
                return Fail<IUnencryptedPayload>(new ArgumentNullException(nameof(secret)));
            if (!secret.IsValid())
                return Fail<IUnencryptedPayload>(new ArgumentException(nameof(secret)));
            if (salt is null)
                return Fail<IUnencryptedPayload>(new ArgumentNullException(nameof(salt)));
            if (!salt.IsValid())
                return Fail<IUnencryptedPayload>(new ArgumentException(nameof(salt)));

            System.Security.Cryptography.Aes algorithm = default;
            try
            {
                var success = false;
                Exception error = default;
                (success, error, algorithm) = AesProvider.GetAlgorithm();
                if (!success)
                    return Fail<IUnencryptedPayload>(error);
                if (algorithm is null)
                    return Fail<IUnencryptedPayload>(new NullReferenceException("Error fetching algorithm - algorithm provided is null"));

                algorithm.Padding = PaddingMode.PKCS7;
                algorithm.Mode = CipherMode.CBC;
                algorithm.Key = secret.Value;
                algorithm.IV = salt.Value;
                using var encryptor = algorithm.CreateDecryptor();
                using var ms = new MemoryStream(payload.Value);
                using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Read);
                using var reader = new BinaryReader(cs);
                var result = new List<byte>();
                var bufferSize = 1024;
                byte[] buffer = new byte[bufferSize];
                bool ReadData()
                {
                    var read = reader.Read(buffer, 0, bufferSize);
                    if (read > 0)
                        result.AddRange(buffer.Take(read));
                    return 0 == read;
                }
                while (ReadData()) ;
                return Succeed(new UnencryptedPayload(result.ToArray()) as IUnencryptedPayload);
            }
            catch (Exception error)
            {
                return Fail<IUnencryptedPayload>(error);
            }
            finally
            {
                algorithm?.Dispose();
            }
        }
    }

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

    /// <summary>
    /// Implements <see cref="IAesProvider"/> using <see cref="RSACryptoServiceProvider"/>
    /// </summary>
    public sealed class AesCryptoSvcProvider : IAesProvider
    {
        /// <inheritdoc/>
        public Result<System.Security.Cryptography.Aes> GetAlgorithm()
        {
            try
            {
                return Succeed(new AesCryptoServiceProvider() as System.Security.Cryptography.Aes);
            }
            catch (Exception error)
            {
                return Fail<System.Security.Cryptography.Aes>(error);
            }
        }
    }

    /// <summary>
    /// Specialization of <see cref="AesCryptoServiceBase"/> using <see cref="AesCryptoServiceProvider"/>
    /// </summary>
    public sealed class AesCryptoServiceProviderBasedCryptoService : AesCryptoServiceBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AesCryptoServiceProviderBasedCryptoService() : base(new AesCryptoSvcProvider()) { }
    }

    /// <summary>
    /// Implements <see cref="IAesProvider"/> using <see cref="AesCng"/>
    /// </summary>
    public sealed class AesManagedProvider : IAesProvider
    {
        /// <inheritdoc/>
        public Result<System.Security.Cryptography.Aes> GetAlgorithm()
        {
            try
            {
                return Succeed(new AesManaged() as System.Security.Cryptography.Aes);
            }
            catch (Exception error)
            {
                return Fail<System.Security.Cryptography.Aes>(error);
            }
        }
    }

    /// <summary>
    /// Specialization of <see cref="AesCryptoServiceBase"/> using <see cref="AesManaged"/>
    /// </summary>
    public sealed class AesManagedBasedCryptoService : AesCryptoServiceBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AesManagedBasedCryptoService() : base(new AesManagedProvider()) { }
    }

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

    /// <summary>
    /// Implements <see cref="IRandomSecretAndSaltProvider"/>
    /// </summary>
    public sealed class RandomSecretAndSaltProvider : IRandomSecretAndSaltProvider
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithmProvider">The <see cref="IAesProvider"/></param>
        public RandomSecretAndSaltProvider(IAesProvider algorithmProvider) =>
            AlgorithmProvider = algorithmProvider ?? throw new ArgumentNullException(nameof(algorithmProvider));

        internal IAesProvider AlgorithmProvider { get; }

        /// <inheritdoc/>
        public Result<(ISecret Secret, ISalt Salt)> GenerateKeyPair()
        {
            System.Security.Cryptography.Aes algorithm = default;
            try
            {
                var success = false;
                Exception error = default;
                (success, error, algorithm) = AlgorithmProvider.GetAlgorithm();
                if (!success)
                    return Fail<(ISecret, ISalt)>(error);
                algorithm.GenerateKey();
                algorithm.GenerateIV();
                var secret = new Secret(algorithm.Key) as ISecret;
                var salt = new Salt(algorithm.IV) as ISalt;
                return Succeed((secret, salt));
            }
            catch (Exception error)
            {
                return Fail<(ISecret, ISalt)>(error);
            }
            finally
            {
                algorithm?.Dispose();
            }
        }
    }
}
