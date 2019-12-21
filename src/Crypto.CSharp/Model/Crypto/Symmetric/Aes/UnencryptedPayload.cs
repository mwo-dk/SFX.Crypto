using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes
{
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
