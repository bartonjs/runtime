// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    /// <summary>
    ///   Represents an HPKE key pair bound to a specific ciphersuite.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///     This algorithm is specified by RFC 9180.
    ///   </para>
    ///   <para>
    ///     An <see cref="Hpke" /> instance represents the KEM key material (encapsulation key,
    ///     and optionally a decapsulation key) associated with a particular <see cref="HpkeSuite" />.
    ///   </para>
    ///   <para>
    ///     Developers are encouraged to program against the <c>Hpke</c> base class,
    ///     rather than any specific derived class.
    ///     The derived classes are intended for interop with the underlying system
    ///     cryptographic libraries.
    ///   </para>
    /// </remarks>
    public abstract partial class Hpke : IDisposable
    {
        private bool _disposed;

        /// <summary>
        ///   Gets a value that indicates whether HPKE is supported on the current platform.
        /// </summary>
        /// <value>
        ///   <see langword="true" /> if HPKE is supported; otherwise, <see langword="false" />.
        /// </value>
        public static bool IsSupported { get; } = HpkeImplementation.SupportsAny();

        /// <summary>
        ///   Gets the HPKE ciphersuite for this instance.
        /// </summary>
        /// <value>
        ///   The HPKE ciphersuite for this instance.
        /// </value>
        public HpkeSuite Suite { get; }

        /// <summary>
        ///   Initializes a new instance of the <see cref="Hpke" /> class.
        /// </summary>
        /// <param name="suite">
        ///   The HPKE ciphersuite for this instance.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="suite" /> is <see langword="null" />.
        /// </exception>
        protected Hpke(HpkeSuite suite)
        {
            ArgumentNullException.ThrowIfNull(suite);
            Suite = suite;
        }

        internal void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

        private void ValidateSenderKey(Hpke senderKey)
        {
            ArgumentNullException.ThrowIfNull(senderKey);
            senderKey.ThrowIfDisposed();

            if (!Suite.Equals(senderKey.Suite))
            {
                throw new ArgumentException(SR.Cryptography_HpkeKeyMismatch, nameof(senderKey));
            }
        }

        /// <summary>
        ///   Generates a new HPKE key pair.
        /// </summary>
        /// <param name="suite">
        ///   The HPKE ciphersuite to generate a key pair for.
        /// </param>
        /// <returns>
        ///   The generated key, containing both encapsulation and decapsulation key material.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="suite" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred generating the HPKE key pair.
        /// </exception>
        /// <exception cref="PlatformNotSupportedException">
        ///   The platform does not support HPKE. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports HPKE.
        /// </exception>
        public static Hpke GenerateKey(HpkeSuite suite)
        {
            ArgumentNullException.ThrowIfNull(suite);

            return HpkeImplementation.GenerateKeyCore(suite);
        }

        /// <summary>
        ///   Imports an encapsulation key (public key) for the specified suite.
        /// </summary>
        /// <param name="suite">
        ///   The HPKE ciphersuite for the key.
        /// </param>
        /// <param name="source">
        ///   The buffer containing the encapsulation key to import.
        /// </param>
        /// <returns>
        ///   An <see cref="Hpke" /> instance containing only the encapsulation key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="suite" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="source" /> is not the correct size for the specified suite.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   The key could not be imported.
        /// </exception>
        public static Hpke ImportEncapsulationKey(HpkeSuite suite, ReadOnlySpan<byte> source)
        {
            ArgumentNullException.ThrowIfNull(suite);

            return HpkeImplementation.ImportEncapsulationKeyCore(suite, source);
        }

        /// <summary>
        ///   Imports an encapsulation key (public key) for the specified suite.
        /// </summary>
        /// <param name="suite">
        ///   The HPKE ciphersuite for the key.
        /// </param>
        /// <param name="source">
        ///   The byte array containing the encapsulation key to import.
        /// </param>
        /// <returns>
        ///   An <see cref="Hpke" /> instance containing only the encapsulation key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="suite" /> or <paramref name="source" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="source" /> is not the correct size for the specified suite.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   The key could not be imported.
        /// </exception>
        public static Hpke ImportEncapsulationKey(HpkeSuite suite, byte[] source)
        {
            ArgumentNullException.ThrowIfNull(suite);
            ArgumentNullException.ThrowIfNull(source);

            return ImportEncapsulationKey(suite, new ReadOnlySpan<byte>(source));
        }

        /// <summary>
        ///   Imports a decapsulation key (private key) for the specified suite.
        /// </summary>
        /// <param name="suite">
        ///   The HPKE ciphersuite for the key.
        /// </param>
        /// <param name="source">
        ///   The buffer containing the decapsulation key to import.
        /// </param>
        /// <returns>
        ///   An <see cref="Hpke" /> instance containing both the decapsulation and encapsulation keys.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="suite" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="source" /> is not the correct size for the specified suite.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   The key could not be imported.
        /// </exception>
        public static Hpke ImportDecapsulationKey(HpkeSuite suite, ReadOnlySpan<byte> source)
        {
            ArgumentNullException.ThrowIfNull(suite);

            return HpkeImplementation.ImportDecapsulationKeyCore(suite, source);
        }

        /// <summary>
        ///   Imports a decapsulation key (private key) for the specified suite.
        /// </summary>
        /// <param name="suite">
        ///   The HPKE ciphersuite for the key.
        /// </param>
        /// <param name="source">
        ///   The byte array containing the decapsulation key to import.
        /// </param>
        /// <returns>
        ///   An <see cref="Hpke" /> instance containing both the decapsulation and encapsulation keys.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="suite" /> or <paramref name="source" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="source" /> is not the correct size for the specified suite.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   The key could not be imported.
        /// </exception>
        public static Hpke ImportDecapsulationKey(HpkeSuite suite, byte[] source)
        {
            ArgumentNullException.ThrowIfNull(suite);
            ArgumentNullException.ThrowIfNull(source);

            return ImportDecapsulationKey(suite, new ReadOnlySpan<byte>(source));
        }

        /// <summary>
        ///   Exports the encapsulation key (public key) into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the encapsulation key.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="destination" /> is not the correct size.
        ///   The required size can be determined from <see cref="HpkeSuite.EncapsulationKeySizeInBytes" />.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void ExportEncapsulationKey(Span<byte> destination)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (destination.Length != Suite.EncapsulationKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulationKeySizeInBytes),
                    nameof(destination));
            }

            ExportEncapsulationKeyCore(destination);
        }

        /// <summary>
        ///   Exports the encapsulation key (public key).
        /// </summary>
        /// <returns>
        ///   A byte array containing the encapsulation key.
        /// </returns>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] ExportEncapsulationKey()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            byte[] destination = new byte[Suite.EncapsulationKeySizeInBytes];
            ExportEncapsulationKeyCore(destination);

            return destination;
        }

        /// <summary>
        ///   Exports the decapsulation key (private key) into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the decapsulation key.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="destination" /> is not the correct size.
        ///   The required size can be determined from <see cref="HpkeSuite.DecapsulationKeySizeInBytes" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   This instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void ExportDecapsulationKey(Span<byte> destination)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (destination.Length != Suite.DecapsulationKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.DecapsulationKeySizeInBytes),
                    nameof(destination));
            }

            ExportDecapsulationKeyCore(destination);
        }

        /// <summary>
        ///   Exports the decapsulation key (private key).
        /// </summary>
        /// <returns>
        ///   A byte array containing the decapsulation key.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   This instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] ExportDecapsulationKey()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            byte[] destination = new byte[Suite.DecapsulationKeySizeInBytes];
            ExportDecapsulationKeyCore(destination);

            return destination;
        }

        /// <summary>
        ///   Encrypts and authenticates a single plaintext message for the recipient represented by this key
        ///   using Base mode HPKE.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext to encrypt.
        /// </param>
        /// <param name="kemCiphertext">
        ///   The buffer to receive the KEM ciphertext, which the recipient needs for decryption.
        /// </param>
        /// <param name="ciphertext">
        ///   The buffer to receive the AEAD ciphertext and authentication tag.
        ///   This must be exactly <paramref name="plaintext" />.Length + <see cref="HpkeSuite.AeadTagSizeInBytes" /> bytes.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size, or
        ///   <paramref name="ciphertext" /> is not the correct size.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred during encryption.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Seal(
            ReadOnlySpan<byte> plaintext,
            Span<byte> kemCiphertext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> aad = default,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            if (ciphertext.Length != plaintext.Length + Suite.AeadTagSizeInBytes)
            {
                throw new ArgumentException(
                    SR.Argument_CiphertextLengthPlaintextPlusTag,
                    nameof(ciphertext));
            }

            SealCore(plaintext, kemCiphertext, ciphertext, aad, info);
        }

        /// <summary>
        ///   Encrypts and authenticates a single plaintext message for the recipient represented by this key
        ///   using Base mode HPKE.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext to encrypt.
        /// </param>
        /// <param name="kemCiphertext">
        ///   When this method returns, contains the KEM ciphertext produced by the sender, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="ciphertext">
        ///   When this method returns, contains the AEAD ciphertext and authentication tag produced by the sender.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <exception cref="CryptographicException">
        ///   An error occurred during encryption.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Seal(
            ReadOnlySpan<byte> plaintext,
            out byte[] kemCiphertext,
            out byte[] ciphertext,
            ReadOnlySpan<byte> aad = default,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            kemCiphertext = new byte[Suite.EncapsulatedKeySizeInBytes];
            ciphertext = new byte[plaintext.Length + Suite.AeadTagSizeInBytes];

            SealCore(plaintext, kemCiphertext, ciphertext, aad, info);
        }

        /// <summary>
        ///   Encrypts and authenticates a single plaintext message for the recipient represented by this key
        ///   using Base mode HPKE.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext to encrypt.
        /// </param>
        /// <param name="kemCiphertext">
        ///   When this method returns, contains the KEM ciphertext produced by the sender, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="ciphertext">
        ///   When this method returns, contains the AEAD ciphertext and authentication tag produced by the sender.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data, or <see langword="null" /> for none.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <exception cref="CryptographicException">
        ///   An error occurred during encryption.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Seal(
            byte[] plaintext,
            out byte[] kemCiphertext,
            out byte[] ciphertext,
            byte[]? aad = null,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(plaintext);

            Seal(
                new ReadOnlySpan<byte>(plaintext),
                out kemCiphertext,
                out ciphertext,
                new ReadOnlySpan<byte>(aad),
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Decrypts and authenticates a single ciphertext message using Base mode HPKE.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="ciphertext">
        ///   The AEAD ciphertext and authentication tag to decrypt.
        /// </param>
        /// <param name="plaintext">
        ///   The buffer to receive the decrypted plaintext.
        ///   This must be exactly <paramref name="ciphertext" />.Length - <see cref="HpkeSuite.AeadTagSizeInBytes" /> bytes.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size, or
        ///   <paramref name="plaintext" /> is not the correct size, or
        ///   <paramref name="ciphertext" /> is too small to contain a valid authentication tag.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   Decryption failed, or this instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Open(
            ReadOnlySpan<byte> kemCiphertext,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> aad = default,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            if (ciphertext.Length < Suite.AeadTagSizeInBytes)
            {
                throw new ArgumentException(
                    SR.Argument_CiphertextTooSmall,
                    nameof(ciphertext));
            }

            if (plaintext.Length != ciphertext.Length - Suite.AeadTagSizeInBytes)
            {
                throw new ArgumentException(
                    SR.Argument_PlaintextLengthCiphertextMinusTag,
                    nameof(plaintext));
            }

            OpenCore(kemCiphertext, ciphertext, plaintext, aad, info);
        }

        /// <summary>
        ///   Decrypts and authenticates a single ciphertext message using Base mode HPKE.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="ciphertext">
        ///   The AEAD ciphertext and authentication tag to decrypt.
        /// </param>
        /// <param name="plaintext">
        ///   The byte array to receive the decrypted plaintext.
        ///   This must be exactly <paramref name="ciphertext" />.Length - <see cref="HpkeSuite.AeadTagSizeInBytes" /> bytes.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data, or <see langword="null" /> for none.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="kemCiphertext" />, <paramref name="ciphertext" />, or <paramref name="plaintext" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size, or
        ///   <paramref name="plaintext" /> is not the correct size, or
        ///   <paramref name="ciphertext" /> is too small to contain a valid authentication tag.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   Decryption failed, or this instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void Open(
            byte[] kemCiphertext,
            byte[] ciphertext,
            byte[] plaintext,
            byte[]? aad = null,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(kemCiphertext);
            ArgumentNullException.ThrowIfNull(ciphertext);
            ArgumentNullException.ThrowIfNull(plaintext);

            Open(
                new ReadOnlySpan<byte>(kemCiphertext),
                new ReadOnlySpan<byte>(ciphertext),
                new Span<byte>(plaintext),
                new ReadOnlySpan<byte>(aad),
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Decrypts and authenticates a single ciphertext message using Base mode HPKE.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="ciphertext">
        ///   The AEAD ciphertext and authentication tag to decrypt.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   The decrypted plaintext.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size, or
        ///   <paramref name="ciphertext" /> is too small to contain a valid authentication tag.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   Decryption failed, or this instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] Open(
            ReadOnlySpan<byte> kemCiphertext,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> aad = default,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            if (ciphertext.Length < Suite.AeadTagSizeInBytes)
            {
                throw new ArgumentException(
                    SR.Argument_CiphertextTooSmall,
                    nameof(ciphertext));
            }

            byte[] plaintext = new byte[ciphertext.Length - Suite.AeadTagSizeInBytes];
            OpenCore(kemCiphertext, ciphertext, plaintext, aad, info);

            return plaintext;
        }

        /// <summary>
        ///   Decrypts and authenticates a single ciphertext message using Base mode HPKE.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="ciphertext">
        ///   The AEAD ciphertext and authentication tag to decrypt.
        /// </param>
        /// <param name="aad">
        ///   The additional authenticated data, or <see langword="null" /> for none.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <returns>
        ///   The decrypted plaintext.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="kemCiphertext" /> or <paramref name="ciphertext" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size, or
        ///   <paramref name="ciphertext" /> is too small to contain a valid authentication tag.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   Decryption failed, or this instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] Open(
            byte[] kemCiphertext,
            byte[] ciphertext,
            byte[]? aad = null,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(kemCiphertext);
            ArgumentNullException.ThrowIfNull(ciphertext);

            return Open(
                new ReadOnlySpan<byte>(kemCiphertext),
                new ReadOnlySpan<byte>(ciphertext),
                new ReadOnlySpan<byte>(aad),
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption, writing the KEM ciphertext
        ///   into the provided buffer.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The buffer to receive the KEM ciphertext, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeSenderContext SetupSender(
            Span<byte> kemCiphertext,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            return SetupSenderCore(kemCiphertext, info);
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption, writing the KEM ciphertext
        ///   into the provided byte array.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The byte array to receive the KEM ciphertext, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="kemCiphertext" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeSenderContext SetupSender(
            byte[] kemCiphertext,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(kemCiphertext);

            return SetupSender(
                new Span<byte>(kemCiphertext),
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   When this method returns, contains the KEM ciphertext produced by the sender, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeSenderContext SetupSender(
            out byte[] kemCiphertext,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            kemCiphertext = new byte[Suite.EncapsulatedKeySizeInBytes];

            return SetupSenderCore(kemCiphertext, info);
        }

        /// <summary>
        ///   Creates a receiver decryption context for multi-message decryption.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A receiver context that can be used for sequential decryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the receiver context, or this instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeReceiverContext SetupReceiver(
            ReadOnlySpan<byte> kemCiphertext,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            return SetupReceiverCore(kemCiphertext, info);
        }

        /// <summary>
        ///   Creates a receiver decryption context for multi-message decryption.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <returns>
        ///   A receiver context that can be used for sequential decryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="kemCiphertext" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the receiver context, or this instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeReceiverContext SetupReceiver(
            byte[] kemCiphertext,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(kemCiphertext);

            return SetupReceiver(
                new ReadOnlySpan<byte>(kemCiphertext),
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption using PSK mode,
        ///   writing the KEM ciphertext into the provided buffer.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The buffer to receive the KEM ciphertext, which the recipient needs to create the
        ///   corresponding receiver context. This must be exactly
        ///   <see cref="HpkeSuite.EncapsulatedKeySizeInBytes" /> bytes long.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        ///   -or-
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeSenderContext SetupSenderPsk(
            Span<byte> kemCiphertext,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            if (psk.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(psk));
            }

            if (pskId.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(pskId));
            }

            return SetupSenderPskCore(kemCiphertext, info, psk, pskId);
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption using PSK mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   When this method returns, contains the KEM ciphertext produced by the sender, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeSenderContext SetupSenderPsk(
            out byte[] kemCiphertext,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (psk.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(psk));
            }

            if (pskId.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(pskId));
            }

            kemCiphertext = new byte[Suite.EncapsulatedKeySizeInBytes];

            return SetupSenderPskCore(kemCiphertext, info, psk, pskId);
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption using PSK mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   When this method returns, contains the KEM ciphertext produced by the sender, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="psk" /> is <see langword="null" />.
        ///   -or-
        ///   <paramref name="pskId" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeSenderContext SetupSenderPsk(
            out byte[] kemCiphertext,
            byte[] psk,
            byte[] pskId,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(psk);
            ArgumentNullException.ThrowIfNull(pskId);

            return SetupSenderPsk(
                out kemCiphertext,
                new ReadOnlySpan<byte>(psk),
                new ReadOnlySpan<byte>(pskId),
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Creates a receiver decryption context for multi-message decryption using PSK mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A receiver context that can be used for sequential decryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        ///   -or-
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the receiver context, or this instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeReceiverContext SetupReceiverPsk(
            ReadOnlySpan<byte> kemCiphertext,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            if (psk.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(psk));
            }

            if (pskId.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(pskId));
            }

            return SetupReceiverPskCore(kemCiphertext, info, psk, pskId);
        }

        /// <summary>
        ///   Creates a receiver decryption context for multi-message decryption using PSK mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <returns>
        ///   A receiver context that can be used for sequential decryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="kemCiphertext" /> is <see langword="null" />.
        ///   -or-
        ///   <paramref name="psk" /> is <see langword="null" />.
        ///   -or-
        ///   <paramref name="pskId" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        ///   -or-
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the receiver context, or this instance does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public HpkeReceiverContext SetupReceiverPsk(
            byte[] kemCiphertext,
            byte[] psk,
            byte[] pskId,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(kemCiphertext);
            ArgumentNullException.ThrowIfNull(psk);
            ArgumentNullException.ThrowIfNull(pskId);

            return SetupReceiverPsk(
                new ReadOnlySpan<byte>(kemCiphertext),
                new ReadOnlySpan<byte>(psk),
                new ReadOnlySpan<byte>(pskId),
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption using Auth mode,
        ///   writing the KEM ciphertext into the provided buffer.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The buffer to receive the KEM ciphertext, which the recipient needs to create the
        ///   corresponding receiver context. This must be exactly
        ///   <see cref="HpkeSuite.EncapsulatedKeySizeInBytes" /> bytes long.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context, or <paramref name="senderKey" /> does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeSenderContext SetupSenderAuth(
            Span<byte> kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ValidateSenderKey(senderKey);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            return SetupSenderAuthCore(kemCiphertext, senderKey, info);
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption using Auth mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   When this method returns, contains the KEM ciphertext produced by the sender, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context, or <paramref name="senderKey" /> does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeSenderContext SetupSenderAuth(
            out byte[] kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ValidateSenderKey(senderKey);

            kemCiphertext = new byte[Suite.EncapsulatedKeySizeInBytes];

            return SetupSenderAuthCore(kemCiphertext, senderKey, info);
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption using Auth mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   When this method returns, contains the KEM ciphertext produced by the sender, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context, or <paramref name="senderKey" /> does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeSenderContext SetupSenderAuth(
            out byte[] kemCiphertext,
            Hpke senderKey,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(senderKey);

            return SetupSenderAuth(out kemCiphertext, senderKey, new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Creates a receiver decryption context for multi-message decryption using Auth mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A receiver context that can be used for sequential decryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the receiver context, this instance does not contain a decapsulation key,
        ///   or <paramref name="senderKey" /> is not valid.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeReceiverContext SetupReceiverAuth(
            ReadOnlySpan<byte> kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ValidateSenderKey(senderKey);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            return SetupReceiverAuthCore(kemCiphertext, senderKey, info);
        }

        /// <summary>
        ///   Creates a receiver decryption context for multi-message decryption using Auth mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <returns>
        ///   A receiver context that can be used for sequential decryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="kemCiphertext" /> is <see langword="null" />.
        ///   -or-
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the receiver context, this instance does not contain a decapsulation key,
        ///   or <paramref name="senderKey" /> is not valid.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeReceiverContext SetupReceiverAuth(
            byte[] kemCiphertext,
            Hpke senderKey,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(kemCiphertext);
            ArgumentNullException.ThrowIfNull(senderKey);

            return SetupReceiverAuth(
                new ReadOnlySpan<byte>(kemCiphertext),
                senderKey,
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption using AuthPSK mode,
        ///   writing the KEM ciphertext into the provided buffer.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The buffer to receive the KEM ciphertext, which the recipient needs to create the
        ///   corresponding receiver context. This must be exactly
        ///   <see cref="HpkeSuite.EncapsulatedKeySizeInBytes" /> bytes long.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        ///   -or-
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context, or <paramref name="senderKey" /> does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeSenderContext SetupSenderAuthPsk(
            Span<byte> kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ValidateSenderKey(senderKey);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            if (psk.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(psk));
            }

            if (pskId.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(pskId));
            }

            return SetupSenderAuthPskCore(kemCiphertext, senderKey, info, psk, pskId);
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption using AuthPSK mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   When this method returns, contains the KEM ciphertext produced by the sender, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context, or <paramref name="senderKey" /> does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeSenderContext SetupSenderAuthPsk(
            out byte[] kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ValidateSenderKey(senderKey);

            if (psk.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(psk));
            }

            if (pskId.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(pskId));
            }

            kemCiphertext = new byte[Suite.EncapsulatedKeySizeInBytes];

            return SetupSenderAuthPskCore(kemCiphertext, senderKey, info, psk, pskId);
        }

        /// <summary>
        ///   Creates a sender encryption context for multi-message encryption using AuthPSK mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   When this method returns, contains the KEM ciphertext produced by the sender, which the recipient needs to create the
        ///   corresponding receiver context.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <returns>
        ///   A sender context that can be used for sequential encryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        ///   -or-
        ///   <paramref name="psk" /> is <see langword="null" />.
        ///   -or-
        ///   <paramref name="pskId" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the sender context, or <paramref name="senderKey" /> does not contain a decapsulation key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeSenderContext SetupSenderAuthPsk(
            out byte[] kemCiphertext,
            Hpke senderKey,
            byte[] psk,
            byte[] pskId,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(senderKey);
            ArgumentNullException.ThrowIfNull(psk);
            ArgumentNullException.ThrowIfNull(pskId);

            return SetupSenderAuthPsk(
                out kemCiphertext,
                senderKey,
                new ReadOnlySpan<byte>(psk),
                new ReadOnlySpan<byte>(pskId),
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   Creates a receiver decryption context for multi-message decryption using AuthPSK mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule.
        /// </param>
        /// <returns>
        ///   A receiver context that can be used for sequential decryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        ///   -or-
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the receiver context, this instance does not contain a decapsulation key,
        ///   or <paramref name="senderKey" /> is not valid.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeReceiverContext SetupReceiverAuthPsk(
            ReadOnlySpan<byte> kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId,
            ReadOnlySpan<byte> info = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ValidateSenderKey(senderKey);

            if (kemCiphertext.Length != Suite.EncapsulatedKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, Suite.EncapsulatedKeySizeInBytes),
                    nameof(kemCiphertext));
            }

            if (psk.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(psk));
            }

            if (pskId.IsEmpty)
            {
                throw new ArgumentException(SR.Argument_EmptySpan, nameof(pskId));
            }

            return SetupReceiverAuthPskCore(kemCiphertext, senderKey, info, psk, pskId);
        }

        /// <summary>
        ///   Creates a receiver decryption context for multi-message decryption using AuthPSK mode.
        /// </summary>
        /// <param name="kemCiphertext">
        ///   The KEM ciphertext produced by the sender.
        /// </param>
        /// <param name="senderKey">
        ///   The sender's static key.
        /// </param>
        /// <param name="psk">
        ///   The pre-shared key.
        /// </param>
        /// <param name="pskId">
        ///   The pre-shared key identifier.
        /// </param>
        /// <param name="info">
        ///   The info parameter for the HPKE key schedule, or <see langword="null" /> for none.
        /// </param>
        /// <returns>
        ///   A receiver context that can be used for sequential decryption and secret export operations.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="kemCiphertext" /> is <see langword="null" />.
        ///   -or-
        ///   <paramref name="senderKey" /> is <see langword="null" />.
        ///   -or-
        ///   <paramref name="psk" /> is <see langword="null" />.
        ///   -or-
        ///   <paramref name="pskId" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="kemCiphertext" /> is not the correct size.
        ///   -or-
        ///   <paramref name="psk" /> is empty.
        ///   -or-
        ///   <paramref name="pskId" /> is empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred creating the receiver context, this instance does not contain a decapsulation key,
        ///   or <paramref name="senderKey" /> is not valid.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The object has already been disposed.
        ///   -or-
        ///   <paramref name="senderKey" /> has already been disposed.
        /// </exception>
        public HpkeReceiverContext SetupReceiverAuthPsk(
            byte[] kemCiphertext,
            Hpke senderKey,
            byte[] psk,
            byte[] pskId,
            byte[]? info = null)
        {
            ArgumentNullException.ThrowIfNull(kemCiphertext);
            ArgumentNullException.ThrowIfNull(senderKey);
            ArgumentNullException.ThrowIfNull(psk);
            ArgumentNullException.ThrowIfNull(pskId);

            return SetupReceiverAuthPsk(
                new ReadOnlySpan<byte>(kemCiphertext),
                senderKey,
                new ReadOnlySpan<byte>(psk),
                new ReadOnlySpan<byte>(pskId),
                new ReadOnlySpan<byte>(info));
        }

        /// <summary>
        ///   When overridden in a derived class, exports the encapsulation key into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the encapsulation key.
        ///   The buffer is guaranteed to be the correct size.
        /// </param>
        protected abstract void ExportEncapsulationKeyCore(Span<byte> destination);

        /// <summary>
        ///   When overridden in a derived class, exports the decapsulation key into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the decapsulation key.
        ///   The buffer is guaranteed to be the correct size.
        /// </param>
        protected abstract void ExportDecapsulationKeyCore(Span<byte> destination);

        /// <summary>
        ///   When overridden in a derived class, performs single-shot Base mode HPKE encryption.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <param name="kemCiphertext">The buffer to receive the KEM ciphertext.</param>
        /// <param name="ciphertext">The buffer to receive the AEAD ciphertext and tag.</param>
        /// <param name="aad">The additional authenticated data.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        protected abstract void SealCore(
            ReadOnlySpan<byte> plaintext,
            Span<byte> kemCiphertext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> aad,
            ReadOnlySpan<byte> info);

        /// <summary>
        ///   When overridden in a derived class, performs single-shot Base mode HPKE decryption.
        /// </summary>
        /// <param name="kemCiphertext">The KEM ciphertext produced by the sender.</param>
        /// <param name="ciphertext">The AEAD ciphertext and tag to decrypt.</param>
        /// <param name="plaintext">The buffer to receive the decrypted plaintext.</param>
        /// <param name="aad">The additional authenticated data.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        protected abstract void OpenCore(
            ReadOnlySpan<byte> kemCiphertext,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> aad,
            ReadOnlySpan<byte> info);

        /// <summary>
        ///   When overridden in a derived class, creates a sender encryption context using Base mode.
        /// </summary>
        /// <param name="kemCiphertext">The buffer to receive the KEM ciphertext.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        /// <returns>A sender encryption context.</returns>
        protected abstract HpkeSenderContext SetupSenderCore(
            Span<byte> kemCiphertext,
            ReadOnlySpan<byte> info);

        /// <summary>
        ///   When overridden in a derived class, creates a sender encryption context using PSK mode.
        /// </summary>
        /// <param name="kemCiphertext">The buffer to receive the KEM ciphertext.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        /// <param name="psk">The pre-shared key.</param>
        /// <param name="pskId">The pre-shared key identifier.</param>
        /// <returns>A sender encryption context.</returns>
        protected abstract HpkeSenderContext SetupSenderPskCore(
            Span<byte> kemCiphertext,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId);

        /// <summary>
        ///   When overridden in a derived class, creates a sender encryption context using Auth mode.
        /// </summary>
        /// <param name="kemCiphertext">The buffer to receive the KEM ciphertext.</param>
        /// <param name="senderKey">The sender's static key.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        /// <returns>A sender encryption context.</returns>
        protected abstract HpkeSenderContext SetupSenderAuthCore(
            Span<byte> kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> info);

        /// <summary>
        ///   When overridden in a derived class, creates a sender encryption context using AuthPSK mode.
        /// </summary>
        /// <param name="kemCiphertext">The buffer to receive the KEM ciphertext.</param>
        /// <param name="senderKey">The sender's static key.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        /// <param name="psk">The pre-shared key.</param>
        /// <param name="pskId">The pre-shared key identifier.</param>
        /// <returns>A sender encryption context.</returns>
        protected abstract HpkeSenderContext SetupSenderAuthPskCore(
            Span<byte> kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId);

        /// <summary>
        ///   When overridden in a derived class, creates a receiver decryption context using Base mode.
        /// </summary>
        /// <param name="kemCiphertext">The KEM ciphertext produced by the sender.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        /// <returns>A receiver decryption context.</returns>
        protected abstract HpkeReceiverContext SetupReceiverCore(
            ReadOnlySpan<byte> kemCiphertext,
            ReadOnlySpan<byte> info);

        /// <summary>
        ///   When overridden in a derived class, creates a receiver decryption context using PSK mode.
        /// </summary>
        /// <param name="kemCiphertext">The KEM ciphertext produced by the sender.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        /// <param name="psk">The pre-shared key.</param>
        /// <param name="pskId">The pre-shared key identifier.</param>
        /// <returns>A receiver decryption context.</returns>
        protected abstract HpkeReceiverContext SetupReceiverPskCore(
            ReadOnlySpan<byte> kemCiphertext,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId);

        /// <summary>
        ///   When overridden in a derived class, creates a receiver decryption context using Auth mode.
        /// </summary>
        /// <param name="kemCiphertext">The KEM ciphertext produced by the sender.</param>
        /// <param name="senderKey">The sender's static key.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        /// <returns>A receiver decryption context.</returns>
        protected abstract HpkeReceiverContext SetupReceiverAuthCore(
            ReadOnlySpan<byte> kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> info);

        /// <summary>
        ///   When overridden in a derived class, creates a receiver decryption context using AuthPSK mode.
        /// </summary>
        /// <param name="kemCiphertext">The KEM ciphertext produced by the sender.</param>
        /// <param name="senderKey">The sender's static key.</param>
        /// <param name="info">The info parameter for the key schedule.</param>
        /// <param name="psk">The pre-shared key.</param>
        /// <param name="pskId">The pre-shared key identifier.</param>
        /// <returns>A receiver decryption context.</returns>
        protected abstract HpkeReceiverContext SetupReceiverAuthPskCore(
            ReadOnlySpan<byte> kemCiphertext,
            Hpke senderKey,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId);

        /// <summary>
        ///   Releases the resources used by this <see cref="Hpke" /> instance.
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
        ///   Releases the resources used by this <see cref="Hpke" /> instance.
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
