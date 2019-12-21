using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Signature
{
    /// <summary>
    /// Implements <see cref="IVerificationKey"/>
    /// </summary>
    public sealed class VerificationKey : ValidatableByteArray, IVerificationKey
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public VerificationKey(byte[] value) : base(value) { }
    }
}
