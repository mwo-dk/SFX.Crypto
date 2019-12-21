using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Interface describing a encryption key
    /// </summary>
    public interface IUnencryptedPayload : IValidatable
    {
        /// <summary>
        /// The actual payload value
        /// </summary>
        byte[] Value { get; }
    }
}
