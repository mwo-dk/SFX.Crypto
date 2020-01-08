using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Crypto.Symmetric.Rijndael
{
    /// <summary>
    /// Interface describing encryption salt (initialization vector)
    /// </summary>
    public interface ISalt : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }
}
