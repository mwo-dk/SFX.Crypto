namespace SFX.Crypto.CSharp.Model.Shared
{
    internal static class ByreArrayExtensions
    {
        internal static bool IsNotNullNorEmpty(this byte[] data) =>
            !(data is null) && data.Length > 0;
    }
}
