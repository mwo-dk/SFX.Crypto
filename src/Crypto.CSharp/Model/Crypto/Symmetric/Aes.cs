using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Interface describing an encryption key
    /// </summary>
    public interface ISecret : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }

    /// <summary>
    /// Implements <see cref="ISecret"/>
    /// </summary>
    public sealed class Secret : ValidatableByteArray, ISecret
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public Secret(byte[] value) : base(value) { }
    }

    /// <summary>
    /// Interface describing encryption salt (initialization vector)
    /// </summary>
    public interface ISalt : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }

    /// <summary>
    /// Implements <see cref="ISalt"/>
    /// </summary>
    public sealed class Salt : ValidatableByteArray, ISalt
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public Salt(byte[] value) : base(value) { }
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
