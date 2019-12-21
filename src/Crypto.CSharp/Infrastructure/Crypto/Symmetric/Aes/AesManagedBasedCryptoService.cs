namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Specialization of <see cref="AesCryptoServiceBase"/> using <see cref="AesManaged"/>
    /// </summary>
    public sealed class AesManagedBasedCryptoService : AesCryptoServiceBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AesManagedBasedCryptoService() : base(new AesManagedProvider()) { }
    }
}
