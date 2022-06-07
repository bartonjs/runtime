// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Formats.Asn1;
using Internal.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    public sealed partial class CertificateRevocationListBuilder
    {
        public static X509Extension BuildCrlDistributionPointExtension(IEnumerable<string> uris, bool critical = false)
        {
            // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
            //
            // DistributionPoint::= SEQUENCE {
            //    distributionPoint[0]     DistributionPointName OPTIONAL,
            //    reasons[1]     ReasonFlags OPTIONAL,
            //    cRLIssuer[2]     GeneralNames OPTIONAL }

            // DistributionPointName::= CHOICE {
            //    fullName[0]     GeneralNames,
            //    nameRelativeToCRLIssuer[1]     RelativeDistinguishedName }

            AsnWriter? writer = null;

            foreach (string uri in uris)
            {
                if (uri is null)
                {
                    throw new ArgumentException(SR.Cryptography_X509_CDP_NullValue, nameof(uris));
                }

                if (writer is null)
                {
                    writer = new AsnWriter(AsnEncodingRules.DER);
                    // CRLDistributionPoints
                    writer.PushSequence();
                }

                // DistributionPoint
                using (writer.PushSequence())
                {
                    // DistributionPoint/DistributionPointName EXPLICIT [0]
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        // DistributionPointName/GeneralName
                        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                        {
                            // GeneralName/Uri
                            writer.WriteCharacterString(
                                UniversalTagNumber.IA5String,
                                uri,
                                new Asn1Tag(TagClass.ContextSpecific, 6));
                        }
                    }
                }
            }

            if (writer is null)
            {
                throw new ArgumentException(SR.Cryptography_X509_CDP_MustNotBuildEmpty, nameof(uris));
            }

            // CRLDistributionPoints
            writer.PopSequence();

            return writer.EncodeToResult(
                static (span, crit) => new X509Extension(Oids.CrlDistributionPoints, span, crit),
                critical);
        }
    }
}
