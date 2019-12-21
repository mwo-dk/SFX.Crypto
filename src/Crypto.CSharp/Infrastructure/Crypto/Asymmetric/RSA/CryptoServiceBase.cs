using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
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
}
