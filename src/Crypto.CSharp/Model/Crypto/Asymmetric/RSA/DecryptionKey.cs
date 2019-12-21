using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA
{
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
}
