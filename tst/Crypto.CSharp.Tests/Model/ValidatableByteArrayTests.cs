using FsCheck;
using FsCheck.Xunit;
using SFX.Crypto.CSharp.Model.Shared;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using static Crypto.CSharp.Tests.TestHelpers;

namespace Crypto.CSharp.Tests.Model
{
    public class ValidatableByteArrayEx : ValidatableByteArray
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The actual value</param>
        public ValidatableByteArrayEx(byte[] value) : base(value) { }
    }

    public sealed class ValidatableByteArrayTests
    {
        #region Type test
        [Fact]
        public void ValidatableByteArrayIsAbstract() =>
            Assert.True(typeof(ValidatableByteArray).IsAbstract);
        #endregion

        #region Initialization tests
        [Fact]
        public void CtorWithNullWorks() =>
            Assert.Null(new ValidatableByteArrayEx(null).Value);

        [Property]
        public Property CtorWithNonNullWorks(NonEmptyArray<byte> data) =>
            (AreEqual(data.Get, new ValidatableByteArrayEx(data.Get).Value)).ToProperty();
        #endregion

        #region IsValid
        [Fact]
        public void IsValidWithNullWorks() =>
            Assert.False(new ValidatableByteArrayEx(null).IsValid());

        [Property]
        public Property IsValidWithNonNullWorks(NonEmptyArray<byte> data) =>
            (new ValidatableByteArrayEx(data.Get).IsValid()).ToProperty();
        #endregion
    }

    public abstract class GenericTest<T, I, IBase>
        where I : IBase
        where T : I
    {
        [Fact]
        public void ClassIsExtended() =>
            Assert.True(typeof(ValidatableByteArray).IsAssignableFrom(typeof(T)));

        [Fact]
        public void ClassIsSealed() =>
            Assert.True(typeof(T).IsSealed);
    }

    namespace RSA
    {
        using SFX.Crypto.CSharp.Model.Crypto.Asymmetric.RSA;

        public sealed class DecryptionKeyTests : GenericTest<DecryptionKey, IDecryptionKey, IValidatable> { }
        public sealed class EncryptionKeyTests : GenericTest<EncryptionKey, IEncryptionKey, IValidatable> { }
        public sealed class EncryptedPayloadTests : GenericTest<EncryptedPayload, IEncryptedPayload, IValidatable> { }
        public sealed class UnencryptedPayloadTests : GenericTest<UnencryptedPayload, IUnencryptedPayload, IValidatable> { }
    }

    namespace Aes
    {
        using SFX.Crypto.CSharp.Model.Crypto.Symmetric.Aes;

        public sealed class SecretTests : GenericTest<Secret, ISecret, IValidatable> { }
        public sealed class SaltTests : GenericTest<Salt, ISalt, IValidatable> { }
        public sealed class EncryptedPayloadTests : GenericTest<EncryptedPayload, IEncryptedPayload, IValidatable> { }
        public sealed class UnencryptedPayloadTests : GenericTest<UnencryptedPayload, IUnencryptedPayload, IValidatable> { }
    }

    namespace SHA512
    {
        using SFX.Crypto.CSharp.Model.Hash.SHA512;

        public sealed class HashTests : GenericTest<Hash, IHash, IValidatable> { }
        public sealed class UnhashedPayloadTests : GenericTest<UnhashedPayload, IUnhashedPayload, IValidatable> { }
    }
}
