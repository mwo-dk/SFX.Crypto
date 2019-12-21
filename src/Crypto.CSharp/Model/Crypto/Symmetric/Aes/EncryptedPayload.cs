using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes
{
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
}
