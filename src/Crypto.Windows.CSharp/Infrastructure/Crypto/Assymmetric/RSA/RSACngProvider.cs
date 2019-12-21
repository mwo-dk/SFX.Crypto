using SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA;
using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Assymmetric.RSA
{
    /// <summary>
    /// Implements <see cref="IRSAProvider"/> using <see cref="RSACng"/>
    /// </summary>
    public sealed class RSACngProvider : IRSAProvider
    {
        /// <inheritdoc/>
        public Result<System.Security.Cryptography.RSA> GetAlgorithm()
        {
            try
            {
                return Succeed(new RSACng() as System.Security.Cryptography.RSA);
            }
            catch (Exception error)
            {
                return Fail<System.Security.Cryptography.RSA>(error);
            }
        }
    }
}
