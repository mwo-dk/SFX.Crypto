using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Signature
{
    /// <summary>
    /// Interface describing a signature
    /// </summary>
    public interface ISignature : IValidatable
    {
        /// <summary>
        /// The actual signature value
        /// </summary>
        byte[] Value { get; }
    }
}
