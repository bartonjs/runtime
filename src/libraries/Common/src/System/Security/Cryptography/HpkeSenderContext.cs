// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    /// <summary>
    ///   Represents the sender side of an established HPKE encryption context,
    ///   providing sequential encryption and secret export operations.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///     Each call to <see cref="Seal(ReadOnlySpan{byte}, Span{byte}, ReadOnlySpan{byte})" />
    ///     uses a nonce derived from the context's base nonce and an internal sequence number,
    ///     which is incremented after each operation.
    ///     Messages must be decrypted in the same order they were encrypted.
    ///   </para>
    /// </remarks>
    public abstract class HpkeSenderContext : IDisposable
    {
        private bool _disposed;

        /// <summary>
        ///   Initializes a new instance of the <see cref="HpkeSenderContext" /> class.
        /// </summary>
        protected HpkeSenderContext()
        {
        }

        /// <summary>
        ///   Encrypts and authenticates the plaintext, writing the ciphertext and authentication tag
        ///   into the provided buffer, and advances the sequence number.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext to encrypt.
        /// </param>
        /// <param name="ciphertext">
        ///   The buffer to receive the AEAD ciphertext and authentication tag.
        ///   This must be exactly <paramref name="plaintext" />.Length + the suite's AEAD tag size in bytes.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="ciphertext" /> is not the correct size.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred during encryption, or the message limit has been reached.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Seal(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> aad = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            SealCore(plaintext, ciphertext, aad);
        }

        /// <summary>
        ///   Encrypts and authenticates the plaintext, and advances the sequence number.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext to encrypt.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data.
        /// </param>
        /// <returns>
        ///   A byte array containing the AEAD ciphertext and authentication tag.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred during encryption, or the message limit has been reached.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] Seal(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            byte[] ciphertext = new byte[plaintext.Length + GetAeadTagSizeInBytes()];
            SealCore(plaintext, ciphertext, aad);

            return ciphertext;
        }

        /// <summary>
        ///   Exports a secret from this HPKE context.
        /// </summary>
        /// <param name="exporterContext">
        ///   The exporter context string, which binds the exported secret to a specific purpose.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the exported secret.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="destination" /> has a length of zero.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Export(ReadOnlySpan<byte> exporterContext, Span<byte> destination)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (destination.Length == 0)
            {
                throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));
            }

            ExportCore(exporterContext, destination);
        }

        /// <summary>
        ///   Exports a secret from this HPKE context.
        /// </summary>
        /// <param name="exporterContext">
        ///   The exporter context string, which binds the exported secret to a specific purpose.
        /// </param>
        /// <param name="length">
        ///   The desired length of the exported secret, in bytes.
        /// </param>
        /// <returns>
        ///   A byte array containing the exported secret.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="length" /> is less than 1.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] Export(ReadOnlySpan<byte> exporterContext, int length)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

            byte[] destination = new byte[length];
            ExportCore(exporterContext, destination);

            return destination;
        }

        /// <summary>
        ///   When overridden in a derived class, encrypts and authenticates the plaintext.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <param name="ciphertext">The buffer to receive the ciphertext and tag.</param>
        /// <param name="aad">The additional authenticated data.</param>
        protected abstract void SealCore(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> aad);

        /// <summary>
        ///   When overridden in a derived class, exports a secret from the HPKE context.
        /// </summary>
        /// <param name="exporterContext">The exporter context string.</param>
        /// <param name="destination">
        ///   The buffer to receive the exported secret.
        ///   The buffer is guaranteed to have a non-zero length.
        /// </param>
        protected abstract void ExportCore(ReadOnlySpan<byte> exporterContext, Span<byte> destination);

        /// <summary>
        ///   When overridden in a derived class, gets the AEAD tag size for this context, in bytes.
        /// </summary>
        /// <returns>The AEAD tag size in bytes.</returns>
        protected abstract int GetAeadTagSizeInBytes();

        /// <summary>
        ///   Releases the resources used by this <see cref="HpkeSenderContext" /> instance.
        /// </summary>
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        ///   Releases the resources used by this <see cref="HpkeSenderContext" /> instance.
        /// </summary>
        /// <param name="disposing">
        ///   <see langword="true" /> to release both managed and unmanaged resources;
        ///   <see langword="false" /> to release only unmanaged resources.
        /// </param>
        protected virtual void Dispose(bool disposing)
        {
            _disposed = true;
        }
    }
}
