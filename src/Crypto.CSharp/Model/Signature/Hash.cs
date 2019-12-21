using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Signature
{
    /// <summary>
    /// Implements <see cref="IHash"/>
    /// </summary>
    public sealed class Hash : ValidatableByteArray, IHash
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public Hash(byte[] value) : base(value) { }
    }
}
