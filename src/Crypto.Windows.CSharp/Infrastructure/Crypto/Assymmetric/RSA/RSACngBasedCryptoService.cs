using SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Assymmetric.RSA
{
    /// <summary>
    /// Specialization of <see cref="CryptoServiceBase"/> using <see cref="RSACng"/>
    /// </summary>
    public sealed class RSACngBasedCryptoService : CryptoServiceBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger">The logger</param>
        public RSACngBasedCryptoService() : base(new RSACngProvider()) { }
    }
}
