using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Interface describing a decryption key
    /// </summary>
    public interface IDecryptionKey : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }
}
