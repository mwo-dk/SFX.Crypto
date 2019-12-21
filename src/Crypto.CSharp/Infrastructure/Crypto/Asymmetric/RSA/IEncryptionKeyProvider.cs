using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;
using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Interface describing the capability of serving <see cref="IEncryptionKey"/>s
    /// </summary>
    public interface IEncryptionKeyProvider
    {
        /// <summary>
        /// Fetches a <see cref="IEncryptionKey"/>
        /// </summary>
        /// <returns></returns>
        Result<IEncryptionKey> GetEncryptionKey();
    }
}
