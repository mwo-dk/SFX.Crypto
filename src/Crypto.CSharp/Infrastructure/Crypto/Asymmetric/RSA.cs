using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Interface describing the capability of serving <see cref="EncryptionKey"/>s
    /// </summary>
    public interface IEncryptionKeyProvider
    {
        /// <summary>
        /// Fetches a <see cref="IEncryptionKey"/>
        /// </summary>
        /// <returns></returns>
        Result<IEncryptionKey> GetEncryptionKey();
    }

    /// <summary>
    /// Interface describing the capability of serving <see cref="DecryptionKey"/>s
    /// </summary>
    public interface IDecryptionKeyProvider
    {
        /// <summary>
        /// Fetches a <see cref="IDecryptionKey"/>
        /// </summary>
        /// <returns></returns>
        Result<IDecryptionKey> GetDecryptionKey();
    }

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

    /// <summary>
    /// Implements <see cref="ICryptoService"/> utilizing RSA
    /// </summary>
    public abstract class CryptoServiceBase : ICryptoService
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rsaProvider">The <see cref="IRSAProvider"/> utilized</param>
        protected CryptoServiceBase(IRSAProvider rsaProvider) =>
            RSAProvider = rsaProvider ?? throw new ArgumentNullException(nameof(rsaProvider));

        internal IRSAProvider RSAProvider { get; }

        /// <inheritdoc/>
        public Result<IEncryptedPayload> Encrypt(IUnencryptedPayload payload, IEncryptionKey key)
        {
            if (payload is null)
                return Fail<IEncryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IEncryptedPayload>(new ArgumentException(nameof(payload)));
            if (key is null)
                return Fail<IEncryptedPayload>(new ArgumentNullException(nameof(key)));
            if (!key.IsValid())
                return Fail<IEncryptedPayload>(new ArgumentException(nameof(key)));

            System.Security.Cryptography.RSA algorithm = default;
            try
            {
                var success = false;
                Exception error = default;
                (success, error, algorithm) = RSAProvider.GetAlgorithm();
                if (!success)
                    return Fail<IEncryptedPayload>(error);
                if (algorithm is null)
                    return Fail<IEncryptedPayload>(new NullReferenceException("Error fetching algorithm - algorithm provided is null"));

                algorithm.ImportRSAPublicKey(key.Value, out var _);
                var result = algorithm.Encrypt(payload.Value, RSAEncryptionPadding.Pkcs1);
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
        public Result<IUnencryptedPayload> Decrypt(IEncryptedPayload payload, IDecryptionKey key)
        {
            if (payload is null)
                return Fail<IUnencryptedPayload>(new ArgumentNullException(nameof(payload)));
            if (!payload.IsValid())
                return Fail<IUnencryptedPayload>(new ArgumentException(nameof(payload)));
            if (key is null)
                return Fail<IUnencryptedPayload>(new ArgumentNullException(nameof(key)));
            if (!key.IsValid())
                return Fail<IUnencryptedPayload>(new ArgumentException(nameof(key)));

            System.Security.Cryptography.RSA algorithm = default;
            try
            {
                var success = false;
                Exception error = default;
                (success, error, algorithm) = RSAProvider.GetAlgorithm();
                if (!success)
                    return Fail<IUnencryptedPayload>(error);
                if (algorithm is null)
                    return Fail<IUnencryptedPayload>(new NullReferenceException("Error fetching algorithm - algorithm provided is null"));

                algorithm.ImportRSAPrivateKey(key.Value, out var _);
                var result = algorithm.Decrypt(payload.Value, RSAEncryptionPadding.Pkcs1);
                return Succeed(new UnencryptedPayload(result) as IUnencryptedPayload);
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

    /// <summary>
    /// Implements <see cref="IRSAProvider"/> using <see cref="RSACryptoServiceProvider"/>
    /// </summary>
    public sealed class RSACryptoSvcProvider : IRSAProvider
    {
        /// <inheritdoc/>
        public Result<System.Security.Cryptography.RSA> GetAlgorithm()
        {
            try
            {
                return Succeed(new RSACryptoServiceProvider() as System.Security.Cryptography.RSA);
            }
            catch (Exception error)
            {
                return Fail<System.Security.Cryptography.RSA>(error);
            }
        }
    }

    /// <summary>
    /// Specialization of <see cref="CryptoServiceBase"/> using <see cref="RSACryptoServiceProvider"/>
    /// </summary>
    public sealed class RSACryptoServiceProviderBasedCryptoService : CryptoServiceBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public RSACryptoServiceProviderBasedCryptoService() : base(new RSACryptoSvcProvider()) { }
    }

    /// <summary>
    /// Interface describing the capability to generate private and public keys
    /// </summary>
    public interface IRandomKeyPairProvider
    {
        /// <summary>
        /// Generates a random key pair for RSA encryption and decryption
        /// </summary>
        /// <returns></returns>
        Result<(IEncryptionKey PublicKey, IDecryptionKey PrivateKey)> GenerateKeyPair();
    }

    /// <summary>
    /// Implements <see cref="IRandomKeyPairProvider"/>
    /// </summary>
    public sealed class RandomKeyPairProvider : IRandomKeyPairProvider
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithmProvider">The <see cref="IRSAProvider"/></param>
        public RandomKeyPairProvider(IRSAProvider algorithmProvider) =>
            AlgorithmProvider = algorithmProvider ?? throw new ArgumentNullException(nameof(algorithmProvider));

        internal IRSAProvider AlgorithmProvider { get; }

        /// <inheritdoc/>
        public Result<(IEncryptionKey PublicKey, IDecryptionKey PrivateKey)> GenerateKeyPair()
        {
            System.Security.Cryptography.RSA algorithm = default;
            try
            {
                var success = false;
                Exception error = default;
                (success, error, algorithm) = AlgorithmProvider.GetAlgorithm();
                if (!success)
                    return Fail<(IEncryptionKey, IDecryptionKey)>(error);
                var publicKey = new EncryptionKey(algorithm.ExportRSAPublicKey()) as IEncryptionKey;
                var privateKey = new DecryptionKey(algorithm.ExportRSAPrivateKey()) as IDecryptionKey;
                return Succeed((publicKey, privateKey));
            }
            catch (Exception error)
            {
                return Fail<(IEncryptionKey, IDecryptionKey)>(error);
            }
            finally
            {
                algorithm?.Dispose();
            }
        }
    }
}
