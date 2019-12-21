using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Interface describing an encryption key
    /// </summary>
    public interface ISecret : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }
}
