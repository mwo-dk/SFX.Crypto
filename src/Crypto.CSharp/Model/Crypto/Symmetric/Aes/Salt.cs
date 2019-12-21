using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes
{
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
}
