// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;

namespace System.Security.Cryptography.X509Certificates
{
    public sealed partial class CertificateRevocationListBuilder
    {
        public byte[] Build(
            X509Certificate2 issuerCertificate,
            BigInteger crlNumber,
            DateTimeOffset nextUpdate,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding? rsaSignaturePadding = null)
        {
            return Build(
                issuerCertificate,
                crlNumber,
                nextUpdate,
                DateTimeOffset.UtcNow,
                hashAlgorithm,
                rsaSignaturePadding);
        }

        public byte[] Build(
            X509Certificate2 issuerCertificate,
            BigInteger crlNumber,
            DateTimeOffset nextUpdate,
            DateTimeOffset thisUpdate,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding? rsaSignaturePadding = null)
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

            ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name, nameof(hashAlgorithm));

            // Check the Basic Constraints and Key Usage extensions to help identify inappropriate certificates.
            // Note that this is not a security check. The system library backing X509Chain will use these same criteria
            // to determine if a chain is valid; and a user can easily call the X509SignatureGenerator overload to
            // bypass this validation.  We're simply helping them at signing time understand that they've
            // chosen the wrong cert.
            var basicConstraints = (X509BasicConstraintsExtension?)issuerCertificate.Extensions[Oids.BasicConstraints2];
            var keyUsage = (X509KeyUsageExtension?)issuerCertificate.Extensions[Oids.KeyUsage];
            var subjectKeyIdentifier =
                (X509SubjectKeyIdentifierExtension?)issuerCertificate.Extensions[Oids.SubjectKeyIdentifier];

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

            AsymmetricAlgorithm? key = null;
            string keyAlgorithm = issuerCertificate.GetKeyAlgorithm();
            X509SignatureGenerator generator;

            try
            {
                switch (keyAlgorithm)
                {
                    case Oids.Rsa:
                        if (rsaSignaturePadding is null)
                        {
                            throw new ArgumentException(
                                "The issuer certificate uses an RSA key, but no RSASignaturePadding value was provided.");
                        }

                        RSA? rsa = issuerCertificate.GetRSAPrivateKey();
                        key = rsa;
                        generator = X509SignatureGenerator.CreateForRSA(rsa!, rsaSignaturePadding);
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

                X509AuthorityKeyIdentifierExtension akid;

                if (subjectKeyIdentifier is not null)
                {
                    akid = X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifier);
                }
                else
                {
                    akid = X509AuthorityKeyIdentifierExtension.CreateFromIssuerNameAndSerialNumber(
                        issuerCertificate.IssuerName,
                        issuerCertificate.SerialNumberBytes.Span);
                }

                return Build(
                    issuerCertificate.SubjectName,
                    generator,
                    crlNumber,
                    nextUpdate,
                    thisUpdate,
                    hashAlgorithm,
                    akid);
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
            HashAlgorithmName hashAlgorithm,
            X509AuthorityKeyIdentifierExtension akid)
        {
            return Build(
                issuerName,
                generator,
                crlNumber,
                nextUpdate,
                DateTimeOffset.UtcNow,
                hashAlgorithm,
                akid);
        }

        public byte[] Build(
            X500DistinguishedName issuerName,
            X509SignatureGenerator generator,
            BigInteger crlNumber,
            DateTimeOffset nextUpdate,
            DateTimeOffset thisUpdate,
            HashAlgorithmName hashAlgorithm,
            X509AuthorityKeyIdentifierExtension akid)
        {
            ArgumentNullException.ThrowIfNull(issuerName);
            ArgumentNullException.ThrowIfNull(generator);

            if (crlNumber < 0)
                throw new ArgumentOutOfRangeException(nameof(crlNumber), SR.ArgumentOutOfRange_NeedNonNegNum);
            if (nextUpdate <= thisUpdate)
                throw new ArgumentException(SR.Cryptography_CRLBuilder_DatesReversed);

            ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name, nameof(hashAlgorithm));
            ArgumentNullException.ThrowIfNull(akid);

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
                                    writer.WriteEncodedValue(revoked.Extensions);
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
    }
}
