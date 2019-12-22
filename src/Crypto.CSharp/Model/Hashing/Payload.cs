using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Hashing
{
    public sealed class Payload : ValidatableByteArray, IPayload
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public Payload(byte[] value) : base(value) { }
    }
}
