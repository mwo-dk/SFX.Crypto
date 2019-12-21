using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Interface describing the capability of serving <see cref="IDecryptionKey"/>s
    /// </summary>
    public interface IDecryptionKeyProvider
    {
        /// <summary>
        /// Fetches a <see cref="IDecryptionKey"/>
        /// </summary>
        /// <returns></returns>
        Result<IDecryptionKey> GetDecryptionKey();
    }
}
