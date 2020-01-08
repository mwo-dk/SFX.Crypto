using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Symmetric.Rijndael
{
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
}
