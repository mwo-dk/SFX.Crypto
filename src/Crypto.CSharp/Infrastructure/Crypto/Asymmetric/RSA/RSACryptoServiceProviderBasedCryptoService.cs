namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Specialization of <see cref="CryptoServiceBase"/> using <see cref="RSACryptoServiceProvider"/>
    /// </summary>
    public sealed class RSACryptoServiceProviderBasedCryptoService : CryptoServiceBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public RSACryptoServiceProviderBasedCryptoService() : base(new RSACryptoSvcProvider()) { }
    }
}
