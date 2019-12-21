using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Implements <see cref="IAesProvider"/> using <see cref="AesCng"/>
    /// </summary>
    public sealed class AesManagedProvider : IAesProvider
    {
        /// <inheritdoc/>
        public Result<System.Security.Cryptography.Aes> GetAlgorithm()
        {
            try
            {
                return Succeed(new AesManaged() as System.Security.Cryptography.Aes);
            }
            catch (Exception error)
            {
                return Fail<System.Security.Cryptography.Aes>(error);
            }
        }
    }
}
