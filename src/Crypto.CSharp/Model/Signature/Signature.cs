using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Signature
{
    /// <summary>
    /// Implements <see cref="ISignature"/>
    /// </summary>
    public sealed class Signature : ValidatableByteArray, ISignature
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public Signature(byte[] value) : base(value) { }
    }
}
