﻿using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Symmetric.Aes
{
    /// <summary>
    /// Implements <see cref="IAesProvider"/> using <see cref="AesCng"/>
    /// </summary>
    public sealed class AesCngProvider : IAesProvider
    {
        /// <inheritdoc/>
        public Result<System.Security.Cryptography.Aes> GetAlgorithm()
        {
            try
            {
                return Succeed(new AesCng() as System.Security.Cryptography.Aes);
            }
            catch (Exception error)
            {
                return Fail<System.Security.Cryptography.Aes>(error);
            }
        }
    }

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
