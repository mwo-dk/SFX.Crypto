using System;
using System.Linq;
using System.Security.Cryptography;

namespace Crypto.CSharp.Tests
{
    internal static class TestHelpers
    {
        internal static bool AreBothNull(byte[] x, byte[] y) =>
            x is null && y is null;
        internal static bool AreEqual(byte[] x, byte[] y) =>
            x.SequenceEqual(y);
    }

    public sealed class FakeAes : Aes
    {
        public static byte[] TheIV = new byte[] { 1, 2, 3 };
        public static byte[] TheKey = new byte[] { 4, 5, 6 };

        private byte[] _iv = default;
        public override byte[] IV { get => _iv; set => _iv = value; }

        private byte[] _key = default;
        public override byte[] Key { get => _key; set => _key = value; }

        public bool GenerateIVInvoked { get; private set; }
        public override void GenerateIV() =>
            (IV, GenerateIVInvoked) = (TheIV, true);

        public bool GenerateKeyInvoked { get; private set; }
        public override void GenerateKey() =>
            (Key, GenerateKeyInvoked) = (TheKey, true);

        public bool DisposeInvoked { get; private set; }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            DisposeInvoked = true;
        }

        #region Ignored
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            throw new NotImplementedException();
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            throw new NotImplementedException();
        }
        #endregion
    }

    public sealed class FakeRSA : RSA
    {
        public static byte[] ThePrivateKey = new byte[] { 1, 2, 3 };
        public static byte[] ThePublicKey = new byte[] { 4, 5, 6 };

        public bool ExportRSAPublicKeyInvoked { get; private set; }
        public override byte[] ExportRSAPublicKey()
        {
            ExportRSAPublicKeyInvoked = true;
            return ThePublicKey;
        }
        public bool ExportRSAPrivateKeyInvoked { get; private set; }
        public override byte[] ExportRSAPrivateKey()
        {
            ExportRSAPrivateKeyInvoked = true;
            return ThePrivateKey;
        }

        #region Ignored
        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            throw new NotImplementedException();
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotImplementedException();
        }
        #endregion

        public bool DisposeInvoked { get; private set; }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            DisposeInvoked = true;
        }
    }
}
