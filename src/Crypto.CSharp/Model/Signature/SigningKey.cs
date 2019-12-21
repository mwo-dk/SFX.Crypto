using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Signature
{
    /// <summary>
    /// Implements <see cref="ISigningKey"/>
    /// </summary>
    public sealed class SigningKey : ValidatableByteArray, ISigningKey
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public SigningKey(byte[] value) : base(value) { }
    }
}
