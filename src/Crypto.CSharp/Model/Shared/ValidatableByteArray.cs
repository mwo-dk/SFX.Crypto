namespace SFX.Crypto.CSharp.Model.Shared
{
    /// <summary>
    /// Base class for all byte array stuff
    /// </summary>
    public abstract class ValidatableByteArray : IValidatable
    {
        private ValidatableByteArray() { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public ValidatableByteArray(byte[] value) => Value = value;

        /// <inheritdoc/>
        public bool IsValid() => Value.IsNotNullNorEmpty();

        /// <inheritdoc/>
        public byte[] Value { get; }
    }
}
