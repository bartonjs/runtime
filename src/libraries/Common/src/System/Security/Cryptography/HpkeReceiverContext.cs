// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    /// <summary>
    ///   Represents the receiver side of an established HPKE encryption context,
    ///   providing sequential decryption and secret export operations.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///     Each call to <see cref="Open(ReadOnlySpan{byte}, Span{byte}, ReadOnlySpan{byte})" />
    ///     uses a nonce derived from the context's base nonce and an internal sequence number,
    ///     which is incremented after each operation. Messages must be decrypted in the same order
    ///     they were encrypted.
    ///   </para>
    /// </remarks>
    public abstract class HpkeReceiverContext : IDisposable
    {
        private bool _disposed;

        /// <summary>
        ///   Initializes a new instance of the <see cref="HpkeReceiverContext" /> class.
        /// </summary>
        protected HpkeReceiverContext()
        {
        }

        /// <summary>
        ///   Decrypts and authenticates the ciphertext, writing the plaintext into the provided buffer,
        ///   and advances the internal sequence number.
        /// </summary>
        /// <param name="ciphertext">
        ///   The AEAD ciphertext and authentication tag to decrypt.
        /// </param>
        /// <param name="plaintext">
        ///   The buffer to receive the decrypted plaintext.
        ///   This must be exactly <paramref name="ciphertext" />.Length - the suite's AEAD tag size in bytes.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="plaintext" /> is not the correct size, or
        ///   <paramref name="ciphertext" /> is too small to contain a valid authentication tag.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   Decryption failed, or the message limit has been reached.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Open(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            OpenCore(ciphertext, plaintext, aad);
        }

        /// <summary>
        ///   Decrypts and authenticates the ciphertext, writing the plaintext into the provided byte array,
        ///   and advances the internal sequence number.
        /// </summary>
        /// <param name="ciphertext">
        ///   The AEAD ciphertext and authentication tag to decrypt.
        /// </param>
        /// <param name="plaintext">
        ///   The byte array to receive the decrypted plaintext.
        ///   This must be exactly <paramref name="ciphertext" />.Length - the suite's AEAD tag size in bytes.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data, or <see langword="null" /> for none.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="ciphertext" /> or <paramref name="plaintext" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="plaintext" /> is not the correct size, or
        ///   <paramref name="ciphertext" /> is too small to contain a valid authentication tag.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   Decryption failed, or the message limit has been reached.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Open(byte[] ciphertext, byte[] plaintext, byte[]? aad = null)
        {
            ArgumentNullException.ThrowIfNull(ciphertext);
            ArgumentNullException.ThrowIfNull(plaintext);

            Open(
                new ReadOnlySpan<byte>(ciphertext),
                new Span<byte>(plaintext),
                new ReadOnlySpan<byte>(aad));
        }

        /// <summary>
        ///   Decrypts and authenticates the ciphertext, and advances the internal sequence number.
        /// </summary>
        /// <param name="ciphertext">
        ///   The AEAD ciphertext and authentication tag to decrypt.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data.
        /// </param>
        /// <returns>
        ///   A byte array containing the decrypted plaintext.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="ciphertext" /> is too small to contain a valid authentication tag.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   Decryption failed, or the message limit has been reached.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] Open(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            int tagSize = GetAeadTagSizeInBytes();

            if (ciphertext.Length < tagSize)
            {
                throw new ArgumentException(SR.Argument_CiphertextTooSmall, nameof(ciphertext));
            }

            byte[] plaintext = new byte[ciphertext.Length - tagSize];
            OpenCore(ciphertext, plaintext, aad);

            return plaintext;
        }

        /// <summary>
        ///   Decrypts and authenticates the ciphertext, advances the internal sequence number,
        ///   and returns the plaintext.
        /// </summary>
        /// <param name="ciphertext">
        ///   The AEAD ciphertext and authentication tag to decrypt.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data, or <see langword="null" /> for none.
        /// </param>
        /// <returns>
        ///   A byte array containing the decrypted plaintext.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="ciphertext" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="ciphertext" /> is too small to contain a valid authentication tag.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   Decryption failed, or the message limit has been reached.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] Open(byte[] ciphertext, byte[]? aad = null)
        {
            ArgumentNullException.ThrowIfNull(ciphertext);

            return Open(
                new ReadOnlySpan<byte>(ciphertext),
                new ReadOnlySpan<byte>(aad));
        }

        /// <summary>
        ///   When overridden in a derived class, decrypts using the internal sequence number.
        /// </summary>
        /// <param name="ciphertext">The AEAD ciphertext and tag.</param>
        /// <param name="plaintext">The buffer to receive the plaintext.</param>
        /// <param name="aad">The additional authenticated data.</param>
        protected abstract void OpenCore(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad);

        /// <summary>
        ///   When overridden in a derived class, gets the AEAD tag size for this context, in bytes.
        /// </summary>
        /// <returns>The AEAD tag size in bytes.</returns>
        protected abstract int GetAeadTagSizeInBytes();

        /// <summary>
        ///   Exports a secret from this Hpke context.
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
        ///   Exports a secret from this Hpke context.
        /// </summary>
        /// <param name="exporterContext">
        ///   The exporter context string, which binds the exported secret to a specific purpose.
        /// </param>
        /// <param name="destination">
        ///   The byte array to receive the exported secret.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="exporterContext" /> or <paramref name="destination" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="destination" /> has a length of zero.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Export(byte[] exporterContext, byte[] destination)
        {
            ArgumentNullException.ThrowIfNull(exporterContext);
            ArgumentNullException.ThrowIfNull(destination);

            Export(
                new ReadOnlySpan<byte>(exporterContext),
                new Span<byte>(destination));
        }

        /// <summary>
        ///   Exports a secret from this Hpke context.
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
        ///   Exports a secret from this Hpke context.
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
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="exporterContext" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="length" /> is less than 1.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] Export(byte[] exporterContext, int length)
        {
            ArgumentNullException.ThrowIfNull(exporterContext);

            return Export(
                new ReadOnlySpan<byte>(exporterContext),
                length);
        }

        /// <summary>
        ///   When overridden in a derived class, exports a secret from the Hpke context.
        /// </summary>
        /// <param name="exporterContext">The exporter context string.</param>
        /// <param name="destination">
        ///   The buffer to receive the exported secret.
        ///   The buffer is guaranteed to have a non-zero length.
        /// </param>
        protected abstract void ExportCore(ReadOnlySpan<byte> exporterContext, Span<byte> destination);

        /// <summary>
        ///   Releases the resources used by this <see cref="HpkeReceiverContext" /> instance.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                Dispose(disposing: true);
                GC.SuppressFinalize(this);
            }
        }

        /// <summary>
        ///   Releases the resources used by this <see cref="HpkeReceiverContext" /> instance.
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
