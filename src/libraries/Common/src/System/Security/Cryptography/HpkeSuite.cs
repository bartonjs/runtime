// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace System.Security.Cryptography
{
    /// <summary>
    ///   Represents a specific Hpke ciphersuite, which is a combination of a KEM, KDF, and AEAD algorithm.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///     This algorithm is specified by RFC 9180.
    ///   </para>
    /// </remarks>
    /// <seealso cref="Hpke" />
    [DebuggerDisplay("{Name,nq}")]
    public sealed class HpkeSuite : IEquatable<HpkeSuite>
    {
        /// <summary>
        ///   Specifies the Key Encapsulation Mechanism (KEM) algorithm for an Hpke ciphersuite.
        /// </summary>
        public enum Kem
        {
            /// <summary>
            ///   DHKEM using NIST P-256 and HKDF-SHA256. IANA value 0x0010.
            /// </summary>
            DHKEM_P256_HKDF_SHA256 = 0x0010,

            /// <summary>
            ///   DHKEM using NIST P-384 and HKDF-SHA384. IANA value 0x0011.
            /// </summary>
            DHKEM_P384_HKDF_SHA384 = 0x0011,

            /// <summary>
            ///   DHKEM using X25519 and HKDF-SHA256. IANA value 0x0020.
            /// </summary>
            DHKEM_X25519_HKDF_SHA256 = 0x0020,
        }

        /// <summary>
        ///   Specifies the Key Derivation Function (KDF) algorithm for an Hpke ciphersuite.
        /// </summary>
        public enum Kdf
        {
            /// <summary>
            ///   HKDF using SHA-256. IANA value 0x0001.
            /// </summary>
            HKDF_SHA256 = 0x0001,

            /// <summary>
            ///   HKDF using SHA-384. IANA value 0x0002.
            /// </summary>
            HKDF_SHA384 = 0x0002,

            /// <summary>
            ///   HKDF using SHA-512. IANA value 0x0003.
            /// </summary>
            HKDF_SHA512 = 0x0003,
        }

        /// <summary>
        ///   Specifies the Authenticated Encryption with Associated Data (AEAD) algorithm for an Hpke ciphersuite.
        /// </summary>
        public enum Aead
        {
            /// <summary>
            ///   AES-128-GCM. IANA value 0x0001.
            /// </summary>
            Aes128Gcm = 0x0001,

            /// <summary>
            ///   AES-256-GCM. IANA value 0x0002.
            /// </summary>
            Aes256Gcm = 0x0002,

            /// <summary>
            ///   ChaCha20-Poly1305. IANA value 0x0003.
            /// </summary>
            ChaCha20Poly1305 = 0x0003,
        }

        /// <summary>
        ///   Gets an Hpke suite using DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
        /// </summary>
        /// <value>
        ///   An Hpke suite using DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
        /// </value>
        public static HpkeSuite DHKEM_P256_HKDF_SHA256_AES_128_GCM { get; } = new(
            Kem.DHKEM_P256_HKDF_SHA256,
            Kdf.HKDF_SHA256,
            Aead.Aes128Gcm);

        /// <summary>
        ///   Gets an Hpke suite using DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, and AES-256-GCM.
        /// </summary>
        /// <value>
        ///   An Hpke suite using DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, and AES-256-GCM.
        /// </value>
        public static HpkeSuite DHKEM_P384_HKDF_SHA384_AES_256_GCM { get; } = new(
            Kem.DHKEM_P384_HKDF_SHA384,
            Kdf.HKDF_SHA384,
            Aead.Aes256Gcm);

        /// <summary>
        ///   Gets an Hpke suite using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
        /// </summary>
        /// <value>
        ///   An Hpke suite using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
        /// </value>
        public static HpkeSuite DHKEM_X25519_HKDF_SHA256_AES_128_GCM { get; } = new(
            Kem.DHKEM_X25519_HKDF_SHA256,
            Kdf.HKDF_SHA256,
            Aead.Aes128Gcm);

        /// <summary>
        ///   Gets an Hpke suite using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20Poly1305.
        /// </summary>
        /// <value>
        ///   An Hpke suite using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20Poly1305.
        /// </value>
        public static HpkeSuite DHKEM_X25519_HKDF_SHA256_ChaCha20Poly1305 { get; } = new(
            Kem.DHKEM_X25519_HKDF_SHA256,
            Kdf.HKDF_SHA256,
            Aead.ChaCha20Poly1305);

        /// <summary>
        ///   Initializes a new instance of the <see cref="HpkeSuite" /> class with the specified
        ///   KEM, KDF, and AEAD algorithms.
        /// </summary>
        /// <param name="kem">
        ///   The Key Encapsulation Mechanism (KEM) algorithm to use.
        /// </param>
        /// <param name="kdf">
        ///   The Key Derivation Function (KDF) algorithm to use.
        /// </param>
        /// <param name="aead">
        ///   The Authenticated Encryption with Associated Data (AEAD) algorithm to use.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="kem" />, <paramref name="kdf" />, or <paramref name="aead" /> is not a defined enum value.
        /// </exception>
        public HpkeSuite(Kem kem, Kdf kdf, Aead aead)
        {
            if (!Enum.IsDefined(kem))
                throw new ArgumentOutOfRangeException(nameof(kem));
            if (!Enum.IsDefined(kdf))
                throw new ArgumentOutOfRangeException(nameof(kdf));
            if (!Enum.IsDefined(aead))
                throw new ArgumentOutOfRangeException(nameof(aead));

            KemAlgorithm = kem;
            KdfAlgorithm = kdf;
            AeadAlgorithm = aead;
        }

        /// <summary>
        ///   Gets the Key Encapsulation Mechanism (KEM) algorithm for this suite.
        /// </summary>
        /// <value>
        ///   The KEM algorithm for this suite.
        /// </value>
        public Kem KemAlgorithm { get; }

        /// <summary>
        ///   Gets the Key Derivation Function (KDF) algorithm for this suite.
        /// </summary>
        /// <value>
        ///   The KDF algorithm for this suite.
        /// </value>
        public Kdf KdfAlgorithm { get; }

        /// <summary>
        ///   Gets the Authenticated Encryption with Associated Data (AEAD) algorithm for this suite.
        /// </summary>
        /// <value>
        ///   The AEAD algorithm for this suite.
        /// </value>
        public Aead AeadAlgorithm { get; }

        /// <summary>
        ///   Gets the name of the Hpke ciphersuite.
        /// </summary>
        /// <value>
        ///   A string representing the Hpke ciphersuite name.
        /// </value>
        public string Name => GetName(KemAlgorithm, KdfAlgorithm, AeadAlgorithm);

        /// <summary>
        ///   Gets the IANA-registered KEM identifier for this suite.
        /// </summary>
        /// <value>
        ///   The two-byte KEM identifier as defined in RFC 9180, Section 7.1.
        /// </value>
        internal ushort KemId => (ushort)KemAlgorithm;

        /// <summary>
        ///   Gets the IANA-registered KDF identifier for this suite.
        /// </summary>
        /// <value>
        ///   The two-byte KDF identifier as defined in RFC 9180, Section 7.2.
        /// </value>
        internal ushort KdfId => (ushort)KdfAlgorithm;

        /// <summary>
        ///   Gets the IANA-registered AEAD identifier for this suite.
        /// </summary>
        /// <value>
        ///   The two-byte AEAD identifier as defined in RFC 9180, Section 7.3.
        /// </value>
        internal ushort AeadId => (ushort)AeadAlgorithm;

        /// <summary>
        ///   Gets the size of the KEM encapsulation key (public key) for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the KEM encapsulation key for this suite, in bytes.
        /// </value>
        public int EncapsulationKeySizeInBytes => KemAlgorithm switch
        {
            Kem.DHKEM_P256_HKDF_SHA256 => 65,
            Kem.DHKEM_P384_HKDF_SHA384 => 97,
            Kem.DHKEM_X25519_HKDF_SHA256 => 32,
            _ => throw new CryptographicException(),
        };

        /// <summary>
        ///   Gets the size of the KEM decapsulation key (private key) for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the KEM decapsulation key for this suite, in bytes.
        /// </value>
        public int DecapsulationKeySizeInBytes => KemAlgorithm switch
        {
            Kem.DHKEM_P256_HKDF_SHA256 => 32,
            Kem.DHKEM_P384_HKDF_SHA384 => 48,
            Kem.DHKEM_X25519_HKDF_SHA256 => 32,
            _ => throw new CryptographicException(),
        };

        /// <summary>
        ///   Gets the size of the KEM encapsulated key (KEM ciphertext) for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the KEM encapsulated key for this suite, in bytes.
        /// </value>
        public int EncapsulatedKeySizeInBytes => KemAlgorithm switch
        {
            Kem.DHKEM_P256_HKDF_SHA256 => 65,
            Kem.DHKEM_P384_HKDF_SHA384 => 97,
            Kem.DHKEM_X25519_HKDF_SHA256 => 32,
            _ => throw new CryptographicException(),
        };

        /// <summary>
        ///   Gets the size of the AEAD key for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the AEAD key for this suite, in bytes.
        /// </value>
        internal int AeadKeySizeInBytes => AeadAlgorithm switch
        {
            Aead.Aes128Gcm => 16,
            Aead.Aes256Gcm => 32,
            Aead.ChaCha20Poly1305 => 32,
            _ => throw new CryptographicException(),
        };

        /// <summary>
        ///   Gets the size of the AEAD nonce for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the AEAD nonce for this suite, in bytes.
        /// </value>
#pragma warning disable CA1822
        internal int AeadNonceSizeInBytes => 12;
#pragma warning restore CA1822

        /// <summary>
        ///   Gets the size of the AEAD authentication tag for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the AEAD authentication tag for this suite, in bytes.
        /// </value>
        public int AeadTagSizeInBytes => 16;

        /// <summary>
        ///   Gets the length of the ciphertext produced by encrypting a plaintext of the specified length.
        /// </summary>
        /// <param name="plaintextLength">
        ///   The length of the plaintext, in bytes.
        /// </param>
        /// <returns>
        ///   The length of the ciphertext, in bytes, which is <paramref name="plaintextLength" /> plus
        ///   <see cref="AeadTagSizeInBytes" />.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="plaintextLength" /> is negative.
        /// </exception>
        public int GetCiphertextLength(int plaintextLength)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength);

            return plaintextLength + AeadTagSizeInBytes;
        }

        /// <summary>
        ///   Compares two <see cref="HpkeSuite" /> objects.
        /// </summary>
        /// <param name="other">
        ///   An object to be compared to the current <see cref="HpkeSuite"/> object.
        /// </param>
        /// <returns>
        ///   <see langword="true" /> if the objects are considered equal; otherwise, <see langword="false" />.
        /// </returns>
        public bool Equals([NotNullWhen(true)] HpkeSuite? other) =>
            other is not null &&
            other.KemAlgorithm == KemAlgorithm &&
            other.KdfAlgorithm == KdfAlgorithm &&
            other.AeadAlgorithm == AeadAlgorithm;

        /// <inheritdoc />
        public override bool Equals([NotNullWhen(true)] object? obj) => obj is HpkeSuite suite && Equals(suite);

        /// <inheritdoc />
        public override int GetHashCode() => HashCode.Combine(KemAlgorithm, KdfAlgorithm, AeadAlgorithm);

        /// <inheritdoc />
        public override string ToString() => Name;

        /// <summary>
        ///   Determines whether two <see cref="HpkeSuite" /> objects specify the same ciphersuite.
        /// </summary>
        /// <param name="left">
        ///   An object that specifies a ciphersuite.
        /// </param>
        /// <param name="right">
        ///   A second object, to be compared to the object that is identified by the <paramref name="left" /> parameter.
        /// </param>
        /// <returns>
        ///   <see langword="true" /> if the objects are considered equal; otherwise, <see langword="false" />.
        /// </returns>
        public static bool operator ==(HpkeSuite? left, HpkeSuite? right)
        {
            return left is null ? right is null : left.Equals(right);
        }

        /// <summary>
        ///   Determines whether two <see cref="HpkeSuite" /> objects do not specify the same ciphersuite.
        /// </summary>
        /// <param name="left">
        ///   An object that specifies a ciphersuite.
        /// </param>
        /// <param name="right">
        ///   A second object, to be compared to the object that is identified by the <paramref name="left" /> parameter.
        /// </param>
        /// <returns>
        ///   <see langword="true" /> if the objects are not considered equal; otherwise, <see langword="false" />.
        /// </returns>
        public static bool operator !=(HpkeSuite? left, HpkeSuite? right)
        {
            return !(left == right);
        }

        private static string GetName(Kem kem, Kdf kdf, Aead aead)
        {
            string kemName = kem switch
            {
                Kem.DHKEM_P256_HKDF_SHA256 => "DHKEM(P-256, HKDF-SHA256)",
                Kem.DHKEM_P384_HKDF_SHA384 => "DHKEM(P-384, HKDF-SHA384)",
                Kem.DHKEM_X25519_HKDF_SHA256 => "DHKEM(X25519, HKDF-SHA256)",
                _ => kem.ToString(),
            };

            string kdfName = kdf switch
            {
                Kdf.HKDF_SHA256 => "HKDF-SHA256",
                Kdf.HKDF_SHA384 => "HKDF-SHA384",
                Kdf.HKDF_SHA512 => "HKDF-SHA512",
                _ => kdf.ToString(),
            };

            string aeadName = aead switch
            {
                Aead.Aes128Gcm => "AES-128-GCM",
                Aead.Aes256Gcm => "AES-256-GCM",
                Aead.ChaCha20Poly1305 => "ChaCha20Poly1305",
                _ => aead.ToString(),
            };

            return $"{kemName}, {kdfName}, {aeadName}";
        }
    }
}
