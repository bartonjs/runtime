// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography.X509Certificates
{
    public sealed partial class CertificateRevocationListBuilder
    {
        private struct RevokedCertificate
        {
            internal byte[] Serial;
            internal DateTimeOffset RevocationTime;
            internal byte[]? Extensions;

            internal RevokedCertificate(ref AsnValueReader reader, int version)
            {
                AsnValueReader revokedCertificate = reader.ReadSequence();
                Serial = revokedCertificate.ReadIntegerBytes().ToArray();
                RevocationTime = ReadX509Time(ref revokedCertificate);
                Extensions = null;

                if (version > 0 && revokedCertificate.HasData)
                {
                    AsnValueReader crlExtensionsExplicit =
                        revokedCertificate.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

                    if (!crlExtensionsExplicit.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    Extensions = crlExtensionsExplicit.ReadEncodedValue().ToArray();
                    crlExtensionsExplicit.ThrowIfNotEmpty();
                }

                revokedCertificate.ThrowIfNotEmpty();
            }
        }

        private List<RevokedCertificate> _revoked;
        private AsnWriter? _writer;

        public HashAlgorithmName? HashAlgorithm { get; set; }
        public RSASignaturePadding? RSASignaturePadding { get; set; }

        public CertificateRevocationListBuilder()
        {
            _revoked = new List<RevokedCertificate>();
        }

        private CertificateRevocationListBuilder(List<RevokedCertificate> revoked)
        {
            Debug.Assert(revoked != null);
            _revoked = revoked;
        }

        public static CertificateRevocationListBuilder Load(byte[] currentCrl, out BigInteger currentCrlNumber)
        {
            ArgumentNullException.ThrowIfNull(currentCrl);

            CertificateRevocationListBuilder ret = Load(
                new ReadOnlySpan<byte>(currentCrl),
                out BigInteger crlNumber,
                out int bytesConsumed);

            if (bytesConsumed != currentCrl.Length)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            currentCrlNumber = crlNumber;
            return ret;
        }

        public static CertificateRevocationListBuilder Load(
            ReadOnlySpan<byte> currentCrl,
            out BigInteger currentCrlNumber,
            out int bytesConsumed)
        {
            List<RevokedCertificate> list = new();
            BigInteger crlNumber = 0;
            int payloadLength;

            try
            {
                AsnValueReader reader = new AsnValueReader(currentCrl, AsnEncodingRules.DER);
                payloadLength = reader.PeekEncodedValue().Length;

                AsnValueReader certificateList = reader.ReadSequence();
                AsnValueReader tbsCertList = certificateList.ReadSequence();
                AlgorithmIdentifierAsn.Decode(ref certificateList, ReadOnlyMemory<byte>.Empty, out _);

                if (!certificateList.TryReadPrimitiveBitString(out _, out _))
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                certificateList.ThrowIfNotEmpty();

                int version = 0;

                if (tbsCertList.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
                {
                    // https://datatracker.ietf.org/doc/html/rfc5280#section-5.1 says the only
                    // version values are v1 (0) and v2 (1).
                    if (!tbsCertList.TryReadInt32(out version) || version != 1)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }
                }

                AlgorithmIdentifierAsn.Decode(ref tbsCertList, ReadOnlyMemory<byte>.Empty, out _);
                // X500DN
                tbsCertList.ReadSequence();

                // thisUpdate
                ReadX509Time(ref tbsCertList);

                // nextUpdate
                ReadX509TimeOpt(ref tbsCertList);

                AsnValueReader revokedCertificates = tbsCertList.ReadSequence();

                if (version > 0 && tbsCertList.HasData)
                {
                    AsnValueReader crlExtensionsExplicit = tbsCertList.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                    AsnValueReader crlExtensions = crlExtensionsExplicit.ReadSequence();
                    crlExtensionsExplicit.ThrowIfNotEmpty();

                    while (crlExtensions.HasData)
                    {
                        AsnValueReader extension = crlExtensions.ReadSequence();
                        string extnId = extension.ReadObjectIdentifier();

                        if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                        {
                            extension.ReadBoolean();
                        }

                        if (!extension.TryReadPrimitiveOctetString(out ReadOnlySpan<byte> extnValue))
                        {
                            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                        }

                        switch (extnId)
                        {
                            case Oids.CrlNumber:
                            {
                                AsnValueReader crlNumberReader = new AsnValueReader(
                                    extnValue,
                                    AsnEncodingRules.DER);

                                crlNumber = crlNumberReader.ReadInteger();
                                crlNumberReader.ThrowIfNotEmpty();

                                break;
                            }

                            case Oids.AuthorityInformationAccess:
                            {
                                AsnValueReader aiaReader = new AsnValueReader(extnValue, AsnEncodingRules.DER);
                                aiaReader.ReadSequence();
                                aiaReader.ThrowIfNotEmpty();
                                break;
                            }
                        }
                    }
                }

                tbsCertList.ThrowIfNotEmpty();

                while (revokedCertificates.HasData)
                {
                    RevokedCertificate revokedCertificate = new RevokedCertificate(ref revokedCertificates, version);
                    list.Add(revokedCertificate);
                }
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }

            bytesConsumed = payloadLength;
            currentCrlNumber = crlNumber;
            return new CertificateRevocationListBuilder(list);
        }

        public static CertificateRevocationListBuilder LoadPem(string currentCrl, out BigInteger currentCrlNumber)
        {
            ArgumentNullException.ThrowIfNull(currentCrl);

            return LoadPem(currentCrl.AsSpan(), out currentCrlNumber);
        }

        public static CertificateRevocationListBuilder LoadPem(ReadOnlySpan<char> currentCrl, out BigInteger currentCrlNumber)
        {
            foreach ((ReadOnlySpan<char> contents, PemFields fields) in new PemEnumerator(currentCrl))
            {
                if (contents[fields.Label].SequenceEqual(PemLabels.X509CertificateRevocationList))
                {
                    byte[] rented = ArrayPool<byte>.Shared.Rent(fields.DecodedDataLength);

                    if (!Convert.TryFromBase64Chars(contents[fields.Base64Data], rented, out int bytesWritten))
                    {
                        Debug.Fail("Base64Decode failed, but PemEncoding said it was legal");
                        throw new UnreachableException();
                    }

                    CertificateRevocationListBuilder ret = Load(
                        rented.AsSpan(0, bytesWritten),
                        out currentCrlNumber,
                        out int bytesConsumed);

                    Debug.Assert(bytesConsumed == bytesWritten);
                    ArrayPool<byte>.Shared.Return(rented);
                    return ret;
                }
            }

            throw new CryptographicException(SR.Cryptography_NoPemOfLabel, PemLabels.X509CertificateRevocationList);
        }

        public void AddEntry(X509Certificate2 certificate)
        {
            AddEntry(certificate, DateTimeOffset.UtcNow);
        }

        public void AddEntry(X509Certificate2 certificate, DateTimeOffset revocationTime)
        {
            ArgumentNullException.ThrowIfNull(certificate);
            AddEntry(certificate.SerialNumberBytes.Span, revocationTime);
        }

        public void AddEntry(byte[] serialNumber)
        {
            AddEntry(serialNumber, DateTimeOffset.UtcNow);
        }

        public void AddEntry(byte[] serialNumber, DateTimeOffset revocationTime)
        {
            ArgumentNullException.ThrowIfNull(serialNumber);

            AddEntry(new ReadOnlySpan<byte>(serialNumber), revocationTime);
        }

        public void AddEntry(ReadOnlySpan<byte> serialNumber)
        {
            AddEntry(serialNumber, DateTimeOffset.UtcNow);
        }

        public void AddEntry(ReadOnlySpan<byte> serialNumber, DateTimeOffset revocationTime)
        {
            if (serialNumber.IsEmpty)
                throw new ArgumentException(SR.Arg_EmptyOrNullArray, nameof(serialNumber));

            _revoked.Add(
                new RevokedCertificate
                {
                    Serial = serialNumber.ToArray(),
                    RevocationTime = revocationTime.ToUniversalTime(),
                });
        }

        public void ExpireEntries(DateTimeOffset oldestRevocationTimeToKeep)
        {
            _revoked.RemoveAll(rc => rc.RevocationTime < oldestRevocationTimeToKeep);
        }

        public byte[] Build(X509Certificate2 issuerCertificate, BigInteger crlNumber, DateTimeOffset nextUpdate)
        {
            return Build(issuerCertificate, crlNumber, nextUpdate, DateTimeOffset.UtcNow);
        }

        public byte[] Build(
            X509Certificate2 issuerCertificate,
            BigInteger crlNumber,
            DateTimeOffset nextUpdate,
            DateTimeOffset thisUpdate)
        {
            ArgumentNullException.ThrowIfNull(issuerCertificate);

            if (!issuerCertificate.HasPrivateKey)
                throw new ArgumentException(
                    SR.Cryptography_CertReq_IssuerRequiresPrivateKey,
                    nameof(issuerCertificate));
            if (crlNumber < 0)
                throw new ArgumentOutOfRangeException(nameof(crlNumber), SR.ArgumentOutOfRange_NeedNonNegNum);
            if (nextUpdate <= thisUpdate)
                throw new ArgumentException(SR.Cryptography_CRLBuilder_DatesReversed);

            // Check the Basic Constraints and Key Usage extensions to help identify inappropriate certificates.
            // Note that this is not a security check. The system library backing X509Chain will use these same criteria
            // to determine if a chain is valid; and a user can easily call the X509SignatureGenerator overload to
            // bypass this validation.  We're simply helping them at signing time understand that they've
            // chosen the wrong cert.
            var basicConstraints = (X509BasicConstraintsExtension?)issuerCertificate.Extensions[Oids.BasicConstraints2];
            var keyUsage = (X509KeyUsageExtension?)issuerCertificate.Extensions[Oids.KeyUsage];
            //var akid = issuerCertificate.Extensions["Oids.Autho"];

            if (basicConstraints == null)
                throw new ArgumentException(
                    SR.Cryptography_CertReq_BasicConstraintsRequired,
                    nameof(issuerCertificate));
            if (!basicConstraints.CertificateAuthority)
                throw new ArgumentException(
                    SR.Cryptography_CertReq_IssuerBasicConstraintsInvalid,
                    nameof(issuerCertificate));
            if (keyUsage != null && (keyUsage.KeyUsages & X509KeyUsageFlags.CrlSign) == 0)
                throw new ArgumentException(SR.Cryptography_CRLBuilder_IssuerKeyUsageInvalid, nameof(issuerCertificate));
            //if (akid is null)
            //    throw new ArgumentException("AKID needed", nameof(issuerCertificate));

            AsymmetricAlgorithm? key = null;
            string keyAlgorithm = issuerCertificate.GetKeyAlgorithm();
            X509SignatureGenerator generator;

            try
            {
                switch (keyAlgorithm)
                {
                    case Oids.Rsa:
                        if (RSASignaturePadding is null)
                        {
                            throw new InvalidOperationException(
                                "The issuer certificate uses an RSA key, but no RSASignaturePadding value was provided.");
                        }

                        RSA? rsa = issuerCertificate.GetRSAPrivateKey();
                        key = rsa;
                        generator = X509SignatureGenerator.CreateForRSA(rsa!, RSASignaturePadding);
                        break;
                    case Oids.EcPublicKey:
                        ECDsa? ecdsa = issuerCertificate.GetECDsaPrivateKey();
                        key = ecdsa;
                        generator = X509SignatureGenerator.CreateForECDsa(ecdsa!);
                        break;
                    default:
                        throw new ArgumentException(
                            SR.Format(SR.Cryptography_UnknownKeyAlgorithm, keyAlgorithm),
                            nameof(issuerCertificate));
                }

                return Build(issuerCertificate.SubjectName, generator, crlNumber, nextUpdate, thisUpdate, null!);
            }
            finally
            {
                key?.Dispose();
            }
        }

        public byte[] Build(
            X500DistinguishedName issuerName,
            X509SignatureGenerator generator,
            BigInteger crlNumber,
            DateTimeOffset nextUpdate,
            X509AuthorityKeyIdentifierExtension akid)
        {
            return Build(issuerName, generator, crlNumber, nextUpdate, DateTimeOffset.UtcNow, akid);
        }

        public byte[] Build(
            X500DistinguishedName issuerName,
            X509SignatureGenerator generator,
            BigInteger crlNumber,
            DateTimeOffset nextUpdate,
            DateTimeOffset thisUpdate,
            X509AuthorityKeyIdentifierExtension akid)
        {
            ArgumentNullException.ThrowIfNull(issuerName);
            ArgumentNullException.ThrowIfNull(generator);

            if (crlNumber < 0)
                throw new ArgumentOutOfRangeException(nameof(crlNumber), SR.ArgumentOutOfRange_NeedNonNegNum);
            if (nextUpdate <= thisUpdate)
                throw new ArgumentException(SR.Cryptography_CRLBuilder_DatesReversed);

            ArgumentNullException.ThrowIfNull(akid);

            HashAlgorithmName hashAlgorithm = HashAlgorithm.GetValueOrDefault();

            if (string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw new InvalidOperationException(
                    "The hash algorithm to use during signing must be specified via the HashAlgorithm property.");
            }

            byte[] signatureAlgId = generator.GetSignatureAlgorithmIdentifier(hashAlgorithm);
            AsnWriter writer = (_writer ??= new AsnWriter(AsnEncodingRules.DER));
            writer.Reset();

            // TBSCertList
            using (writer.PushSequence())
            {
                // version v2(1)
                writer.WriteInteger(1);

                // signature (AlgorithmIdentifier)
                writer.WriteEncodedValue(signatureAlgId);

                // issuer
                writer.WriteEncodedValue(issuerName.RawData);

                // thisUpdate
                WriteX509Time(writer, thisUpdate);

                // nextUpdate
                WriteX509Time(writer, nextUpdate);

                // revokedCertificates (don't write down if empty)
                if (_revoked.Count > 0)
                {
                    // SEQUENCE OF
                    using (writer.PushSequence())
                    {
                        foreach (RevokedCertificate revoked in _revoked)
                        {
                            // Anonymous CRL Entry type
                            using (writer.PushSequence())
                            {
                                writer.WriteInteger(revoked.Serial);
                                WriteX509Time(writer, revoked.RevocationTime);

                                if (revoked.Extensions is not null)
                                {
                                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                                    {
                                        writer.WriteEncodedValue(revoked.Extensions);
                                    }
                                }
                            }
                        }
                    }
                }

                // extensions [0] EXPLICIT Extensions
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    // Extensions (SEQUENCE OF)
                    using (writer.PushSequence())
                    {
                        // Authority Key Identifier Extension
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(akid.Oid!.Value!);

                            if (akid.Critical)
                            {
                                writer.WriteBoolean(true);
                            }

                            writer.WriteOctetString(akid.RawData);
                        }

                        // CRL Number Extension
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier("2.5.29.20");

                            using (writer.PushOctetString())
                            {
                                writer.WriteInteger(crlNumber);
                            }
                        }
                    }
                }
            }

            byte[] tbsCertList = writer.Encode();
            writer.Reset();

            byte[] signature = generator.SignData(tbsCertList, hashAlgorithm);

            // CertificateList
            using (writer.PushSequence())
            {
                writer.WriteEncodedValue(tbsCertList);
                writer.WriteEncodedValue(signatureAlgId);
                writer.WriteBitString(signature);
            }

            byte[] crl = writer.Encode();
            return crl;
        }

        private static DateTimeOffset ReadX509Time(ref AsnValueReader reader)
        {
            if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime))
            {
                return reader.ReadUtcTime();
            }

            return reader.ReadGeneralizedTime();
        }

        private static DateTimeOffset? ReadX509TimeOpt(ref AsnValueReader reader)
        {
            if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime))
            {
                return reader.ReadUtcTime();
            }

            if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.GeneralizedTime))
            {
                return reader.ReadGeneralizedTime();
            }

            return null;
        }

        private static void WriteX509Time(AsnWriter writer, DateTimeOffset time)
        {
            DateTimeOffset timeUtc = time.ToUniversalTime();
            int year = timeUtc.Year;

            if (year >= 1950 && year < 2050)
            {
                writer.WriteUtcTime(timeUtc);
            }
            else
            {
                writer.WriteGeneralizedTime(time, omitFractionalSeconds: true);
            }
        }
    }
}
