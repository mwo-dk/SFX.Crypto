using SFX.Crypto.CSharp.Model.Signature;
using SFX.ROP.CSharp;

namespace SFX.Crypto.CSharp.Infrastructure.Signature
{
    /// <summary>
    /// Interface describing the capability to sign payloads and verify signatures
    /// </summary>
    public interface ISignatureService
    {
        /// <summary>
        /// Signs the <paramref name="payload"/> with the provided public signing key (<paramref name="key"/>)
        /// </summary>
        /// <param name="payload">The payload to sign</param>
        /// <returns><paramref name="payload"/> signed</returns>
        Result<ISignature> SignPayload(IPayload payload);

        /// <summary>
        /// Signs the <paramref name="hash"/> with the provided public signing key (<paramref name="key"/>)
        /// </summary>
        /// <param name="hash">The payload to sign</param>
        /// <returns><paramref name="hash"/> signed</returns>
        Result<ISignature> SignHash(IHash hash);

        /// <summary>
        /// Verifies the signature on <paramref name="signature"/> with the provided verification key (<paramref name="key"/>)
        /// </summary>
        /// <param name="payload">The <see cref="IPayload"/> to verify</param>
        /// <param name="signature">The <see cref="ISignature"/></param>
        /// <returns>The result of the verification</returns>
        Result<bool> VerifyPayload(IPayload payload, ISignature signature);

        /// <summary>
        /// Verifies the signature on <paramref name="hash"/> with the provided verification key (<paramref name="key"/>)
        /// </summary>
        /// <param name="hash">The <see cref="IHash"/> to verify</param>
        /// <param name="signature">The <see cref="ISignature"/></param>
        /// <returns>The result of the verification</returns>
        Result<bool> VerifyHash(IHash hash, ISignature signature);
    }
}
