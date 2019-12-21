using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
{
    /// <summary>
    /// Implements <see cref="IRSAProvider"/> using <see cref="RSACryptoServiceProvider"/>
    /// </summary>
    public sealed class RSACryptoSvcProvider : IRSAProvider
    {
        /// <inheritdoc/>
        public Result<System.Security.Cryptography.RSA> GetAlgorithm()
        {
            try
            {
                return Succeed(new RSACryptoServiceProvider() as System.Security.Cryptography.RSA);
            }
            catch (Exception error)
            {
                return Fail<System.Security.Cryptography.RSA>(error);
            }
        }
    }
}
