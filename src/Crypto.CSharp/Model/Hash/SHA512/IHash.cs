using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Hash.SHA512
{
    /// <summary>
    /// Interface describing a encryption key
    /// </summary>
    public interface IHash : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }
}
