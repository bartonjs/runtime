// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates.Asn1;

namespace System.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///   Represents the Authority Key Identifier X.509 Extension (2.5.29.35).
    /// </summary>
    public sealed class X509AuthorityKeyIdentifierExtension : X509Extension
    {
        private bool _decoded;
        private X500DistinguishedName? _simpleIssuer;
        private ReadOnlyMemory<byte>? _keyIdentifier;
        private ReadOnlyMemory<byte>? _rawIssuer;
        private ReadOnlyMemory<byte>? _serialNumber;

        /// <summary>
        ///   Initializes a new instance of the <see cref="X509AuthorityKeyIdentifierExtension" />
        ///   class.
        /// </summary>
        public X509AuthorityKeyIdentifierExtension()
            : base(Oids.AuthorityKeyIdentifier)
        {
            _decoded = true;
        }

        /// <summary>
        ///   Initializes a new instance of the <see cref="X509AuthorityKeyIdentifierExtension" />
        ///   class from an encoded representation of the extension and an optional critical marker.
        /// </summary>
        /// <param name="rawData">
        ///   The encoded data used to create the extension.
        /// </param>
        /// <param name="critical">
        ///   <see langword="true" /> if the extension is critical;
        ///   otherwise, <see langword="false" />.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="rawData" /> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   <paramref name="rawData" /> did not decode as an Authority Key Identifier extension.
        /// </exception>
        public X509AuthorityKeyIdentifierExtension(byte[] rawData, bool critical = false)
            : base(Oids.AuthorityKeyIdentifier, rawData, critical)
        {
            Decode(RawData);
        }

        /// <summary>
        ///   Initializes a new instance of the <see cref="X509AuthorityKeyIdentifierExtension" />
        ///   class from an encoded representation of the extension and an optional critical marker.
        /// </summary>
        /// <param name="rawData">
        ///   The encoded data used to create the extension.
        /// </param>
        /// <param name="critical">
        ///   <see langword="true" /> if the extension is critical;
        ///   otherwise, <see langword="false" />.
        /// </param>
        /// <exception cref="CryptographicException">
        ///   <paramref name="rawData" /> did not decode as an Authority Key Identifier extension.
        /// </exception>
        public X509AuthorityKeyIdentifierExtension(ReadOnlySpan<byte> rawData, bool critical = false)
            : base(Oids.AuthorityKeyIdentifier, rawData, critical)
        {
            Decode(RawData);
        }

        /// <inheritdoc />
        public override void CopyFrom(AsnEncodedData asnEncodedData)
        {
            base.CopyFrom(asnEncodedData);
            _decoded = false;
        }

        public ReadOnlyMemory<byte>? KeyIdentifier
        {
            get
            {
                if (!_decoded)
                {
                    Decode(RawData);
                }

                return _keyIdentifier;
            }
        }

        public X500DistinguishedName? SimpleIssuer
        {
            get
            {
                if (!_decoded)
                {
                    Decode(RawData);
                }

                return _simpleIssuer;
            }
        }

        public ReadOnlyMemory<byte>? RawIssuer
        {
            get
            {
                if (!_decoded)
                {
                    Decode(RawData);
                }

                return _rawIssuer;
            }
        }

        public ReadOnlyMemory<byte>? SerialNumber
        {
            get
            {
                if (!_decoded)
                {
                    Decode(RawData);
                }

                return _serialNumber;
            }
        }

        public static X509AuthorityKeyIdentifierExtension CreateFromSubjectKeyIdentifier(
            X509SubjectKeyIdentifierExtension subjectKeyIdentifier)
        {
            ArgumentNullException.ThrowIfNull(subjectKeyIdentifier);

            if (!subjectKeyIdentifier.SubjectKeyIdentifierBytes.HasValue)
            {
                throw new ArgumentException("Something about the extension has not had a value provided to it");
            }

            return CreateFromSubjectKeyIdentifier(
                subjectKeyIdentifier.SubjectKeyIdentifierBytes.GetValueOrDefault().Span);
        }

        public static X509AuthorityKeyIdentifierExtension CreateFromSubjectKeyIdentifier(
            byte[] subjectKeyIdentifier)
        {
            ArgumentNullException.ThrowIfNull(subjectKeyIdentifier);

            return CreateFromSubjectKeyIdentifier(new ReadOnlySpan<byte>(subjectKeyIdentifier));
        }

        public static X509AuthorityKeyIdentifierExtension CreateFromSubjectKeyIdentifier(
            ReadOnlySpan<byte> subjectKeyIdentifier)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                writer.WriteOctetString(subjectKeyIdentifier, new Asn1Tag(TagClass.ContextSpecific, 0));
            }

            // Most KeyIdentifier values are computed from SHA-1 (20 bytes), which produces a 24-byte
            // value for this extension.
            // Let's go ahead and be really generous before moving to redundant array allocation.
            Span<byte> stackSpan = stackalloc byte[64];
            ReadOnlySpan<byte> encoded = stackSpan;

            if (writer.TryEncode(stackSpan, out int written))
            {
                encoded = stackSpan.Slice(0, written);
            }
            else
            {
                encoded = writer.Encode();
            }

            return new X509AuthorityKeyIdentifierExtension(encoded);
        }

        public static X509AuthorityKeyIdentifierExtension CreateFromIssuerNameAndSerialNumber(
            X500DistinguishedName issuerName,
            byte[] serialNumber)
        {
            ArgumentNullException.ThrowIfNull(issuerName);
            ArgumentNullException.ThrowIfNull(serialNumber);

            return CreateFromIssuerNameAndSerialNumber(issuerName, new ReadOnlySpan<byte>(serialNumber));
        }

        public static X509AuthorityKeyIdentifierExtension CreateFromIssuerNameAndSerialNumber(
            X500DistinguishedName issuerName,
            ReadOnlySpan<byte> serialNumber)
        {
            ArgumentNullException.ThrowIfNull(issuerName);

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    writer.WriteEncodedValue(issuerName.RawData);
                }

                writer.WriteIntegerUnsigned(serialNumber, new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            return new X509AuthorityKeyIdentifierExtension(writer.Encode());
        }

        public static X509AuthorityKeyIdentifierExtension Create(
            byte[] keyIdentifier,
            X500DistinguishedName issuerName,
            byte[] serialNumber)
        {
            ArgumentNullException.ThrowIfNull(keyIdentifier);
            ArgumentNullException.ThrowIfNull(issuerName);
            ArgumentNullException.ThrowIfNull(serialNumber);

            return Create(
                new ReadOnlySpan<byte>(keyIdentifier),
                issuerName,
                new ReadOnlySpan<byte>(serialNumber));
        }

        public static X509AuthorityKeyIdentifierExtension Create(
            ReadOnlySpan<byte> keyIdentifier,
            X500DistinguishedName issuerName,
            ReadOnlySpan<byte> serialNumber)
        {
            ArgumentNullException.ThrowIfNull(issuerName);

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                writer.WriteOctetString(keyIdentifier, new Asn1Tag(TagClass.ContextSpecific, 0));

                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    writer.WriteEncodedValue(issuerName.RawData);
                }

                writer.WriteIntegerUnsigned(serialNumber, new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            return new X509AuthorityKeyIdentifierExtension(writer.Encode());
        }

        public static X509AuthorityKeyIdentifierExtension CreateFromCertificate(
            X509Certificate2 certificate,
            bool includeKeyIdentifier,
            bool includeIssuerAndSerial)
        {
            ArgumentNullException.ThrowIfNull(certificate);

            X509SubjectKeyIdentifierExtension? skid = null;

            if (includeKeyIdentifier)
            {
                skid = (X509SubjectKeyIdentifierExtension?)certificate.Extensions[Oids.SubjectKeyIdentifier];

                if (skid is null)
                {
                    throw new CryptographicException("Provided certificate does not have a subject key identifier");
                }

                // Only the default constructor for the X509SubjectKeyIdentifierExtension produces null
                Debug.Assert(skid.SubjectKeyIdentifierBytes.HasValue);
                ReadOnlySpan<byte> skidBytes = skid.SubjectKeyIdentifierBytes.GetValueOrDefault().Span;

                if (includeIssuerAndSerial)
                {
                    return Create(
                        skidBytes,
                        certificate.IssuerName,
                        certificate.SerialNumberBytes.Span);
                }

                return CreateFromSubjectKeyIdentifier(skidBytes);
            }
            else if (includeIssuerAndSerial)
            {
                return CreateFromIssuerNameAndSerialNumber(
                    certificate.IssuerName,
                    certificate.SerialNumberBytes.Span);
            }

            Span<byte> emptyExtension = stackalloc byte[] { 0x30, 0x00 };
            return new X509AuthorityKeyIdentifierExtension(emptyExtension);
        }

        private void Decode(ReadOnlySpan<byte> rawData)
        {
            _keyIdentifier = null;
            _simpleIssuer = null;
            _rawIssuer = null;
            _serialNumber = null;

            // https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.1.1
            // AuthorityKeyIdentifier ::= SEQUENCE {
            //    keyIdentifier[0] KeyIdentifier OPTIONAL,
            //    authorityCertIssuer[1] GeneralNames OPTIONAL,
            //    authorityCertSerialNumber[2] CertificateSerialNumber OPTIONAL  }
            //
            // KeyIdentifier::= OCTET STRING

            try
            {
                AsnValueReader reader = new AsnValueReader(rawData, AsnEncodingRules.DER);
                AsnValueReader aki = reader.ReadSequence();
                reader.ThrowIfNotEmpty();

                Asn1Tag nextTag = default;

                if (aki.HasData)
                {
                    nextTag = aki.PeekTag();
                }

                if (nextTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    _keyIdentifier = aki.ReadOctetString(nextTag);

                    if (aki.HasData)
                    {
                        nextTag = aki.PeekTag();
                    }
                }

                if (nextTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    byte[] rawIssuer = aki.ReadOctetString(nextTag);
                    _rawIssuer = rawIssuer;

                    AsnValueReader generalNames = new AsnValueReader(rawIssuer, AsnEncodingRules.DER);
                    bool foundIssuer = false;

                    // Walk all of the entities to make sure they decode legally, so no early abort.
                    while (generalNames.HasData)
                    {
                        GeneralNameAsn.Decode(ref generalNames, rawIssuer, out GeneralNameAsn decoded);

                        if (!foundIssuer && decoded.DirectoryName.HasValue)
                        {
                            // Even if the X500DN fails to load, don't interpret a second one.
                            // That makes the API only ever return "the first directoryName"
                            foundIssuer = true;

                            try
                            {
                                _simpleIssuer = new X500DistinguishedName(decoded.DirectoryName.GetValueOrDefault().Span);
                            }
                            catch (CryptographicException)
                            {
                            }
                        }
                    }

                    if (aki.HasData)
                    {
                        nextTag = aki.PeekTag();
                    }
                }

                if (nextTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
                {
                    _serialNumber = aki.ReadIntegerBytes(nextTag).ToArray();
                }

                aki.ThrowIfNotEmpty();
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }

            _decoded = true;
        }
    }
}
