using System;
using System.Linq;

namespace Crypto.CSharp.Tests
{
    internal static class TestHelpers
    {
        internal static bool AreBothNull(byte[] x, byte[] y) =>
            x is null && y is null;
        internal static bool AreEqual(byte[] x, byte[] y) =>
            x.SequenceEqual(y);
    }
}
