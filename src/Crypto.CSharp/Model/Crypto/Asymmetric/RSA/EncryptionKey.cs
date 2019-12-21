using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA
{
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
}
