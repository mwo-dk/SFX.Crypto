namespace SFX.Crypto.CSharp.Model.Shared
{
    /// <summary>
    /// Interface describing the capability to tell whether an entity is valid or not
    /// </summary>
    public interface IValidatable
    {
        /// <summary>
        /// Answers whether a given payload is valid
        /// </summary>
        /// <returns>If the payload is valid, then true else false</returns>
        bool IsValid();
    }

    /// <summary>
    /// Base class for all byte array stuff
    /// </summary>
    public abstract class ValidatableByteArray
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
