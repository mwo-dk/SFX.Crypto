namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Specialization of <see cref="AesCryptoServiceBase"/> using <see cref="AesCryptoServiceProvider"/>
    /// </summary>
    public sealed class AesCryptoServiceProviderBasedCryptoService : AesCryptoServiceBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AesCryptoServiceProviderBasedCryptoService() : base(new AesCryptoSvcProvider()) { }
    }
}
