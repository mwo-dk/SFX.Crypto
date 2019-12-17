using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Interface describing a encryption key
    /// </summary>
    public interface IEncryptionKey : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }

    /// <summary>
    /// Implements <see cref="IEncryptionKey"/>
    /// </summary>
    public sealed class EncryptionKey : ValidatableByteArray, IEncryptionKey
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public EncryptionKey(byte[] value) : base(value) { }
    }

    /// <summary>
    /// Interface describing a decryption key
    /// </summary>
    public interface IDecryptionKey : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }

    /// <summary>
    /// Implements <see cref="IDecryptionKey"/>
    /// </summary>
    public sealed class DecryptionKey : ValidatableByteArray, IDecryptionKey
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public DecryptionKey(byte[] value) : base(value) { }
    }

    /// <summary>
    /// Interface describing a decryption key
    /// </summary>
    public interface IEncryptedPayload : IValidatable
    {
        /// <summary>
        /// The actual payload value
        /// </summary>
        byte[] Value { get; }
    }

    /// <summary>
    /// Implements <see cref="IEncryptedPayload"/>
    /// </summary>
    public sealed class EncryptedPayload : ValidatableByteArray, IEncryptedPayload
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public EncryptedPayload(byte[] value) : base(value) { }
    }

    /// <summary>
    /// Interface describing a encryption key
    /// </summary>
    public interface IUnencryptedPayload : IValidatable
    {
        /// <summary>
        /// The actual payload value
        /// </summary>
        byte[] Value { get; }
    }

    /// <summary>
    /// Implements <see cref="IUnencryptedPayload"/>
    /// </summary>
    public sealed class UnencryptedPayload : ValidatableByteArray, IUnencryptedPayload
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public UnencryptedPayload(byte[] value) : base(value) { }
    }
}
