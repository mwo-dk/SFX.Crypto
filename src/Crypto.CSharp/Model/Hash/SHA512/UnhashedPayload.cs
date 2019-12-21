using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Hash.SHA512
{
    public sealed class UnhashedPayload : ValidatableByteArray, IUnhashedPayload
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public UnhashedPayload(byte[] value) : base(value) { }
    }
}
