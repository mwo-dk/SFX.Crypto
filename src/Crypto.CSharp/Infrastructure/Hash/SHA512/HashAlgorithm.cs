using SFX.Utils.Infrastructure;
using System;
using static System.Threading.Interlocked;

namespace SFX.Crypto.CSharp.Infrastructure.Hash.SHA512
{
    /// <summary>
    /// Abstraction on top of <see cref="HashAlgorithm"/>
    /// </summary>
    public interface IHashAlgorithm : IDisposable
    {
        /// <summary>
        /// Computes the hash of the provided <paramref name="buffer"/> - direct forward - not utilizing <see cref="OperationResult<>"/>
        /// </summary>
        /// <param name="buffer">The buffer to hash</param>
        /// <returns>The result of the hash</returns>
        byte[] ComputeHash(byte[] buffer);
    }

    /// <summary>
    /// Implements <see cref="IHashAlgorithm"/>
    /// </summary>
    public sealed class HashAlgorithm : IHashAlgorithm, IInitializable
    {
        internal System.Security.Cryptography.SHA512 InnerAlgorithm { get; set; }

        internal long InitializeRunningCount = 0L;
        /// <inheritdoc/>
        public void Initialize()
        {
            try
            {
                if (1L < Increment(ref InitializeRunningCount))
                    return;
                if (IsInitialized())
                    return;

                InnerAlgorithm = System.Security.Cryptography.SHA512.Create();

                Increment(ref InitializationCount);
            }
            finally
            {
                Decrement(ref InitializeRunningCount);
            }
        }

        internal long InitializationCount = 0L;
        /// <inheritdoc/>
        public bool IsInitialized() => 0L < Read(ref InitializationCount);

        /// <inheritdoc/>
        public byte[] ComputeHash(byte[] buffer)
        {
            if (!IsInitialized())
                throw new InvalidOperationException("SHA512HashAlgorithm not initalized");

            return InnerAlgorithm.ComputeHash(buffer);
        }

        internal long DisposeCount = 0L;
        private bool IsDisposed() => 0L < Read(ref DisposeCount);

        /// <inheritdoc/>
        public void Dispose()
        {
            if (!IsInitialized())
                return;
            if (1L < Increment(ref DisposeCount))
                return;

            InnerAlgorithm.Dispose();
            InnerAlgorithm = default;
        }
    }
}
