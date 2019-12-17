using SFX.Crypto.CSharp.Model.Shared;

namespace SFX.Crypto.CSharp.Model.Hash.SHA512
{
    /// <summary>
    /// Interface describing a encryption key
    /// </summary>
    public interface IHash : IValidatable
    {
        /// <summary>
        /// The actual key value
        /// </summary>
        byte[] Value { get; }
    }

    public sealed class Hash : ValidatableByteArray, IHash
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public Hash(byte[] value) : base(value) { }
    }

    /// <summary>
    /// Interface describing a encryption key
    /// </summary>
    public interface IUnhashedPayload : IValidatable
    {
        /// <summary>
        /// The actual payload value
        /// </summary>
        byte[] Value { get; }
    }

    public sealed class UnhashedPayload : ValidatableByteArray, IUnhashedPayload
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public UnhashedPayload(byte[] value) : base(value) { }
    }
}
