namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Specialization of <see cref="AesCryptoServiceBase"/> using <see cref="AesCng"/>
    /// </summary>
    public sealed class AesCngBasedCryptoService : AesCryptoServiceBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AesCngBasedCryptoService() : base(new AesCngProvider()) { }
    }
}
