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
}
