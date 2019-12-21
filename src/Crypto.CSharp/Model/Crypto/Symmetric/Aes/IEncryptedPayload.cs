using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Interface describing a decryption key
    /// </summary>
    public interface IEncryptedPayload : IValidatable
    {
        /// <summary>
        /// The actual payload value
        /// </summary>
        byte[] Value { get; }
    }
}
