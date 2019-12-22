using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Hashing
{
    /// <summary>
    /// Interface describing a encryption key
    /// </summary>
    public interface IPayload : IValidatable
    {
        /// <summary>
        /// The actual payload value
        /// </summary>
        byte[] Value { get; }
    }
}
