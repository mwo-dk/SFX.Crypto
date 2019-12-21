using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Signature
{
    /// <summary>
    /// Interface describing an unsigned hash
    /// </summary>
    public interface IHash : IValidatable
    {
        /// <summary>
        /// The actual value
        /// </summary>
        byte[] Value { get; }
    }
}
