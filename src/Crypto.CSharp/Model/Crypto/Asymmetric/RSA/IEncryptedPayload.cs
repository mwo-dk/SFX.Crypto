using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA
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
