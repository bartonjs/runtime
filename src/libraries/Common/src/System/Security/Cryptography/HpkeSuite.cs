// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace System.Security.Cryptography
{
    /// <summary>
    ///   Represents a specific HPKE ciphersuite, which is a combination of a KEM, KDF, and AEAD algorithm.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///     This algorithm is specified by RFC 9180.
    ///   </para>
    /// </remarks>
    /// <seealso cref="HPKE" />
    [DebuggerDisplay("{Name,nq}")]
    public sealed class HpkeSuite : IEquatable<HpkeSuite>
    {
        /// <summary>
        ///   Gets an HPKE suite using DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
        /// </summary>
        /// <value>
        ///   An HPKE suite using DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
        /// </value>
        public static HpkeSuite DHKEM_P256_HKDF_SHA256_AES_128_GCM { get; } = new(
            "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM",
            kemId: 0x0010,
            kdfId: 0x0001,
            aeadId: 0x0001,
            encapsulationKeySizeInBytes: 65,
            decapsulationKeySizeInBytes: 32,
            encapsulatedKeySizeInBytes: 65,
            aeadKeySizeInBytes: 16,
            aeadNonceSizeInBytes: 12,
            aeadTagSizeInBytes: 16);

        /// <summary>
        ///   Gets an HPKE suite using DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, and AES-256-GCM.
        /// </summary>
        /// <value>
        ///   An HPKE suite using DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, and AES-256-GCM.
        /// </value>
        public static HpkeSuite DHKEM_P384_HKDF_SHA384_AES_256_GCM { get; } = new(
            "DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM",
            kemId: 0x0011,
            kdfId: 0x0002,
            aeadId: 0x0002,
            encapsulationKeySizeInBytes: 97,
            decapsulationKeySizeInBytes: 48,
            encapsulatedKeySizeInBytes: 97,
            aeadKeySizeInBytes: 32,
            aeadNonceSizeInBytes: 12,
            aeadTagSizeInBytes: 16);

        /// <summary>
        ///   Gets an HPKE suite using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
        /// </summary>
        /// <value>
        ///   An HPKE suite using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
        /// </value>
        public static HpkeSuite DHKEM_X25519_HKDF_SHA256_AES_128_GCM { get; } = new(
            "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM",
            kemId: 0x0020,
            kdfId: 0x0001,
            aeadId: 0x0001,
            encapsulationKeySizeInBytes: 32,
            decapsulationKeySizeInBytes: 32,
            encapsulatedKeySizeInBytes: 32,
            aeadKeySizeInBytes: 16,
            aeadNonceSizeInBytes: 12,
            aeadTagSizeInBytes: 16);

        /// <summary>
        ///   Gets an HPKE suite using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20Poly1305.
        /// </summary>
        /// <value>
        ///   An HPKE suite using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20Poly1305.
        /// </value>
        public static HpkeSuite DHKEM_X25519_HKDF_SHA256_ChaCha20Poly1305 { get; } = new(
            "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305",
            kemId: 0x0020,
            kdfId: 0x0001,
            aeadId: 0x0003,
            encapsulationKeySizeInBytes: 32,
            decapsulationKeySizeInBytes: 32,
            encapsulatedKeySizeInBytes: 32,
            aeadKeySizeInBytes: 32,
            aeadNonceSizeInBytes: 12,
            aeadTagSizeInBytes: 16);

        private HpkeSuite(
            string name,
            ushort kemId,
            ushort kdfId,
            ushort aeadId,
            int encapsulationKeySizeInBytes,
            int decapsulationKeySizeInBytes,
            int encapsulatedKeySizeInBytes,
            int aeadKeySizeInBytes,
            int aeadNonceSizeInBytes,
            int aeadTagSizeInBytes)
        {
            Name = name;
            KemId = kemId;
            KdfId = kdfId;
            AeadId = aeadId;
            EncapsulationKeySizeInBytes = encapsulationKeySizeInBytes;
            DecapsulationKeySizeInBytes = decapsulationKeySizeInBytes;
            EncapsulatedKeySizeInBytes = encapsulatedKeySizeInBytes;
            AeadKeySizeInBytes = aeadKeySizeInBytes;
            AeadNonceSizeInBytes = aeadNonceSizeInBytes;
            AeadTagSizeInBytes = aeadTagSizeInBytes;
        }

        /// <summary>
        ///   Gets the name of the HPKE ciphersuite.
        /// </summary>
        /// <value>
        ///   A string representing the HPKE ciphersuite name.
        /// </value>
        public string Name { get; }

        /// <summary>
        ///   Gets the IANA-registered KEM identifier for this suite.
        /// </summary>
        /// <value>
        ///   The two-byte KEM identifier as defined in RFC 9180, Section 7.1.
        /// </value>
        internal ushort KemId { get; }

        /// <summary>
        ///   Gets the IANA-registered KDF identifier for this suite.
        /// </summary>
        /// <value>
        ///   The two-byte KDF identifier as defined in RFC 9180, Section 7.2.
        /// </value>
        internal ushort KdfId { get; }

        /// <summary>
        ///   Gets the IANA-registered AEAD identifier for this suite.
        /// </summary>
        /// <value>
        ///   The two-byte AEAD identifier as defined in RFC 9180, Section 7.3.
        /// </value>
        internal ushort AeadId { get; }

        /// <summary>
        ///   Gets the size of the KEM encapsulation key (public key) for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the KEM encapsulation key for this suite, in bytes.
        /// </value>
        public int EncapsulationKeySizeInBytes { get; }

        /// <summary>
        ///   Gets the size of the KEM decapsulation key (private key) for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the KEM decapsulation key for this suite, in bytes.
        /// </value>
        public int DecapsulationKeySizeInBytes { get; }

        /// <summary>
        ///   Gets the size of the KEM encapsulated key (KEM ciphertext) for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the KEM encapsulated key for this suite, in bytes.
        /// </value>
        public int EncapsulatedKeySizeInBytes { get; }

        /// <summary>
        ///   Gets the size of the AEAD key for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the AEAD key for this suite, in bytes.
        /// </value>
        internal int AeadKeySizeInBytes { get; }

        /// <summary>
        ///   Gets the size of the AEAD nonce for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the AEAD nonce for this suite, in bytes.
        /// </value>
        internal int AeadNonceSizeInBytes { get; }

        /// <summary>
        ///   Gets the size of the AEAD authentication tag for this suite, in bytes.
        /// </summary>
        /// <value>
        ///   The size of the AEAD authentication tag for this suite, in bytes.
        /// </value>
        public int AeadTagSizeInBytes { get; }

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
            other is not null && other.KemId == KemId && other.KdfId == KdfId && other.AeadId == AeadId;

        /// <inheritdoc />
        public override bool Equals([NotNullWhen(true)] object? obj) => obj is HpkeSuite suite && Equals(suite);

        /// <inheritdoc />
        public override int GetHashCode() => HashCode.Combine(KemId, KdfId, AeadId);

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
    }
}
