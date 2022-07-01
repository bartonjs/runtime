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
        private readonly List<RevokedCertificate> _revoked;
        private AsnWriter? _writer;

        public CertificateRevocationListBuilder()
        {
            _revoked = new List<RevokedCertificate>();
        }

        private CertificateRevocationListBuilder(List<RevokedCertificate> revoked)
        {
            Debug.Assert(revoked != null);
            _revoked = revoked;
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
    }
}
