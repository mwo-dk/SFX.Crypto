using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Hash.SHA512
{
    /// <summary>
    /// Interface describing a encryption key
    /// </summary>
    public interface IUnhashedPayload : IValidatable
    {
        /// <summary>
        /// The actual payload value
        /// </summary>
        byte[] Value { get; }
    }
}
