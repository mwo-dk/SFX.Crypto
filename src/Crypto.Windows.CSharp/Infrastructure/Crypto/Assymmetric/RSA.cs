﻿using SFX.ROP.CSharp;
using System;
using System.Security.Cryptography;
using static SFX.ROP.CSharp.Library;

namespace SFX.Crypto.CSharp.Infrastructure.Crypto.Asymmetric.RSA
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
