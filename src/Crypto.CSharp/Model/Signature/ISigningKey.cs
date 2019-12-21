using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Signature
{
    /// <summary>
    /// Interface describing a signing key
    /// </summary>
    public interface ISigningKey : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }
}
