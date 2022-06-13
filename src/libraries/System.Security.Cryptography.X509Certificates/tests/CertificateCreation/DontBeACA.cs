// Licensed to the.NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.CertificateCreation
{
    public static class DontBeACA
    {
        [Fact]
        public static void EndToEnd()
        {
            X500DistinguishedName reqName =
                new X500DistinguishedName("CN=Apple, CN=Banana, OU=Cherry, O=Date, L=Elderberry");

            byte[] pkcs10 = BuildRequest(reqName, "Fig");
            
            using (X509Certificate2 issuerCert = MakeCA())
            {
                CertificateRequest req = IngestRequest(pkcs10, issuerCert);

                byte[] serial = { 1, 1, 2, 3, 5, 8, 13, 21 };
                DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-2);
                DateTimeOffset notAfter = notBefore.AddMinutes(20);

                using (X509Certificate2 issued = req.Create(issuerCert, notBefore, notAfter, serial))
                {
                    Assert.NotNull(issued);
                    AssertExtensions.SequenceEqual(serial, issued.SerialNumberBytes.Span);
                    AssertExtensions.SequenceEqual(reqName.RawData, issued.SubjectName.RawData);
                    AssertExtensions.SequenceEqual(issuerCert.SubjectName.RawData, issued.IssuerName.RawData);
                    Assert.Equal(notBefore.DateTime, issued.NotBefore.ToUniversalTime(), TimeSpan.FromSeconds(1));
                    Assert.Equal(notAfter.DateTime, issued.NotAfter.ToUniversalTime(), TimeSpan.FromSeconds(1));

                    X509ExtensionCollection extensions = issued.Extensions;
                    Assert.Equal(7, extensions.Count);

                    // Extensions are a SEQUENCE OF, not a SET OF, so the order the CA wrote them is the order they appear.
                    Assert.IsType<X509SubjectKeyIdentifierExtension>(extensions[0]);
                    Assert.IsType<X509BasicConstraintsExtension>(extensions[1]);
                    Assert.IsType<X509AuthorityKeyIdentifierExtension>(extensions[2]);
                    Assert.Equal("2.5.29.31", extensions[3].Oid.Value);
                    Assert.IsType<X509AuthorityInformationAccessExtension>(extensions[4]);
                    Assert.IsType<X509KeyUsageExtension>(extensions[5]);
                    Assert.IsType<X509SubjectAlternativeNameExtension>(extensions[6]);
                }
            }

            static CertificateRequest IngestRequest(byte[] pkcs10, X509Certificate2 issuerCert)
            {
                CertificateRequest req = CertificateRequest.LoadSigningRequest(
                    pkcs10,
                    HashAlgorithmName.SHA256,
                    out int bytesConsumed,
                    unsafeLoadCertificateExtensions: true,
                    signerSignaturePadding: RSASignaturePadding.Pss);

                AsnEncodedData? challengePassword = null;

                foreach (AsnEncodedData otherAttribute in req.OtherRequestAttributes)
                {
                    if (otherAttribute?.Oid?.Value == "1.2.840.113549.1.9.7")
                    {
                        if (challengePassword is not null)
                        {
                            throw new InvalidOperationException("Two challenge passwords provided");
                        }

                        challengePassword = otherAttribute;
                    }
                    else
                    {
                        throw new InvalidOperationException(
                            $"Unsupported attribute provided: {otherAttribute.Oid?.Value ?? "(unknown)"}");
                    }
                }

                X509BasicConstraintsExtension? basicConstraints = null;
                X509SubjectKeyIdentifierExtension? skid = null;
                X509EnhancedKeyUsageExtension? eku = null;
                X509KeyUsageExtension? ku = null;
                X509Extension? san = null;

                foreach (X509Extension reqExt in req.CertificateExtensions)
                {
                    if (reqExt is X509BasicConstraintsExtension bcLocal)
                    {
                        if (basicConstraints is not null)
                        {
                            throw new InvalidOperationException("Duplicate Basic Constraints Extension");
                        }

                        if (bcLocal.CertificateAuthority)
                        {
                            throw new InvalidOperationException("Not Authorized to create subordinate CA");
                        }

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
                        //
                        // CAs MUST NOT include the pathLenConstraint field unless the cA
                        // boolean is asserted

                        if (bcLocal.HasPathLengthConstraint)
                        {
                            throw new InvalidOperationException("Invalid Basic Constraints Extension");
                        }

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
                        //
                        // This extension MAY appear as a critical or
                        // non-critical extension in end entity certificates.

                        basicConstraints = bcLocal;
                    }
                    else if (reqExt is X509SubjectKeyIdentifierExtension skidLocal)
                    {
                        if (skid is not null)
                        {
                            throw new InvalidOperationException("Duplicate Subject Key Identifier Extension");
                        }

                        // Note: Another good way to handle this is to just ignore it and replace it.

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
                        //
                        // Conforming CAs MUST mark this extension as non-critical.
                        skidLocal.Critical = false;
                        skid = skidLocal;
                    }
                    else if (reqExt is X509EnhancedKeyUsageExtension ekuLocal)
                    {
                        if (eku is not null)
                        {
                            throw new InvalidOperationException("Duplicate EKU Extension");
                        }

                        foreach (Oid requestedUsage in ekuLocal.EnhancedKeyUsages)
                        {
                            switch (requestedUsage.Value)
                            {
                                // tls-server
                                case "1.3.6.1.5.5.7.3.1":
                                // tls-client
                                case "1.3.6.1.5.5.7.3.2":
                                    break;
                                default:
                                    throw new InvalidOperationException(
                                        $"Unauthorized EKU requested {requestedUsage.Value}");
                            }
                        }

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
                        //
                        // This extension MAY, at the option of the certificate issuer, be
                        // either critical or non-critical.
                        // ...
                        // Conforming CAs
                        // SHOULD NOT mark this extension as critical if the anyExtendedKeyUsage
                        // KeyPurposeId is present.
                        eku = ekuLocal;
                    }
                    else if (reqExt is X509KeyUsageExtension kuLocal)
                    {
                        if (ku is not null)
                        {
                            throw new InvalidOperationException("Duplicate Key Usage Extension");
                        }

                        X509KeyUsageFlags requestedUsages = kuLocal.KeyUsages;

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
                        //
                        // When the
                        // keyUsage extension appears in a certificate, at least one of the bits
                        // MUST be set to 1.

                        if (requestedUsages == 0)
                        {
                            throw new InvalidOperationException("Key Usage contains no usages");
                        }

                        const X509KeyUsageFlags KeyAgreeRestrictions =
                            X509KeyUsageFlags.EncipherOnly |
                            X509KeyUsageFlags.DecipherOnly;

                        const X509KeyUsageFlags PermittedFlags =
                            KeyAgreeRestrictions |
                            X509KeyUsageFlags.KeyAgreement |
                            X509KeyUsageFlags.DataEncipherment |
                            X509KeyUsageFlags.KeyEncipherment |
                            //Deprecated, discouraged to accept.
                            //X509KeyUsageFlags.NonRepudiation |
                            X509KeyUsageFlags.DigitalSignature;

                        if ((requestedUsages & PermittedFlags) != requestedUsages)
                        {
                            throw new InvalidOperationException("Key Usage contains other than permitted flags");
                        }

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
                        //
                        // The meaning of the encipherOnly bit is undefined in the absence of
                        // the keyAgreement bit.
                        // ...
                        // The meaning of the decipherOnly bit is undefined in the absence of
                        // the keyAgreement bit.

                        if ((requestedUsages & KeyAgreeRestrictions) != 0 &&
                            (requestedUsages & X509KeyUsageFlags.KeyAgreement) == 0)
                        {
                            throw new InvalidOperationException("Key Usage contains invalid values");
                        }

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
                        //
                        // When present, conforming CAs
                        // SHOULD mark this extension as critical.
                        kuLocal.Critical = true;
                        ku = kuLocal;
                    }
                    else if (reqExt is X509SubjectAlternativeNameExtension sanLocal)
                    {
                        if (san is not null)
                        {
                            throw new InvalidOperationException("Duplicate Subject Alternative Name Extension");
                        }

                        // CAUTION: DO NOT ACCEPT THIS EXTENSION AS-IS, ALWAYS RE-ENCODE IT.
                        //
                        // This is because the .NET X509SubjectAlternativeNameExtension cannot
                        // describe certain kinds of requested alternative name.
                        //
                        // Instead, loop over the requested names to validate them and build a new extension.
                        //
                        // Unsupported name types are simply ignored.

                        SubjectAlternativeNameBuilder builder = new SubjectAlternativeNameBuilder();
                        bool added = false;

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
                        //
                        // Because the subject alternative name is considered to be definitively
                        // bound to the public key, all parts of the subject alternative name
                        // MUST be verified by the CA.

                        foreach (string dnsName in sanLocal.EnumerateDnsNames())
                        {
                            // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
                            //
                            // Unlike the subject field, conforming CAs MUST
                            // NOT issue certificates with subjectAltNames containing empty
                            // GeneralName fields.

                            if (string.IsNullOrWhiteSpace(dnsName))
                            {
                                throw new InvalidOperationException("Invalid Subject Alternative Name Extension");
                            }

                            // Sanity: .. is never allowed.
                            if (dnsName.Contains(".."))
                            {
                                throw new InvalidOperationException("Invalid Subject Alternative Name Extension");
                            }

                            string trimmed = dnsName.Trim();

                            // If you want to support requests using "fully-qualified DNS" and convert them to
                            // "normal" DNS:
                            if (trimmed.EndsWith('.'))
                            {
                                trimmed = trimmed.Substring(0, trimmed.Length - 1);
                            }

                            // This is a standin for a contextual acceptance test.
                            // It mirrors an authorization for any subdomain of fruit.example,
                            // but not fruit.example itself.
                            if (!trimmed.EndsWith(".fruit.example"))
                            {
                                throw new InvalidOperationException($"Unauthorized requested DNS Name via SAN: {trimmed}");
                            }

                            // Sanity: Don't allow * anywhere after the first position.
                            if (trimmed.IndexOf('*', 1) > 0)
                            {
                                throw new InvalidOperationException("Invalid Subject Alternative Name Extension");
                            }

                            // Sanity: If the first position is '*' then the second is '.'.
                            if (trimmed.StartsWith('*') && trimmed[1] != '.')
                            {
                                throw new InvalidOperationException("Invalid Subject Alternative Name Extension");
                            }

                            // Sanity: Cannot start with '.'
                            if (trimmed.StartsWith('.'))
                            {
                                throw new InvalidOperationException("Invalid Subject Alternative Name Extension");
                            }

                            builder.AddDnsName(trimmed);
                            added = true;
                        }

                        foreach (IPAddress ipAddr in sanLocal.EnumerateIPAddresses())
                        {
                            // This policy represents accepting only values in 10.1.13.0/24, and no IPv6.

                            if (ipAddr.AddressFamily != AddressFamily.InterNetwork)
                            {
                                throw new InvalidOperationException($"Unauthorized requested IP Address via SAN: {ipAddr}");
                            }

                            byte[] addr = ipAddr.GetAddressBytes();

                            if (addr[0] != 10 || addr[1] != 1 || addr[2] != 13)
                            {
                                throw new InvalidOperationException($"Unauthorized requested IP Address via SAN: {ipAddr}");
                            }

                            builder.AddIpAddress(ipAddr);
                            added = true;
                        }

                        // For extra goodness, both the DnsName and IP Address values could/should be checked in a hash set
                        // (or whatever) to filter out duplicates.  For DnsName values duplicates should be determined
                        // after IDNA normalization.
                        //
                        // Yeah, being a CA is hard.

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
                        //
                        // If the subjectAltName extension is present, the sequence MUST contain
                        // at least one entry.

                        if (!added)
                        {
                            throw new InvalidOperationException("SAN extension contained no supported addresses");
                        }

                        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
                        //
                        // If the subject field
                        // contains an empty sequence, then the issuing CA MUST include a
                        // subjectAltName extension that is marked as critical.When including
                        // the subjectAltName extension in a certificate that has a non-empty
                        // subject distinguished name, conforming CAs SHOULD mark the
                        // subjectAltName extension as non-critical.
                        san = builder.Build(req.SubjectName.RawData.Length == 0);
                    }
                    else
                    {
                        // What else would the client request?
                        //
                        // Authority Key Identifier?  That comes from you.
                        // Authority Information Access? Same.
                        // CRL Distribution Points? Same.
                        // Signed Certificate Timestamp? Seems pretty hard without your involvement.
                        // et cetera.
                        //
                        // Anything else in this bucket is just a bad client.
                        //
                        // You're free to ignore AKId/AIA/CDP as "I just requested everything I already had",
                        // but most unknown things should probably be rejected over ignored.
                        //
                        // (Unless you're taking after StartSSL and ignoring literally everything except the
                        // public key because you got all the SAN data and subject and such from elsewhere,
                        // in which case, rock on.)

                        throw new InvalidOperationException(
                            $"Unsupported extension {reqExt.Oid?.Value ?? "(unknown)"} requested.");
                    }
                }

                // Let's fill in what's missing.
                skid ??= new X509SubjectKeyIdentifierExtension(req.PublicKey, false);
                basicConstraints ??= X509BasicConstraintsExtension.CreateForEndEntity();

                // Let's fill in CA responsibilities.
                // For Authority Key Identifier, we'll chain to our Subject Key Identifier if we have one,
                // or our Issuer+Serial if not.
                bool weHaveSkid = issuerCert.Extensions["2.5.29.14"] is not null;
                X509Extension akid =
                    X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuerCert, weHaveSkid, !weHaveSkid);

                X509Extension cdp =
                    CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(
                        new[] { "http://issuer.ca.example/shard.crl" });

                X509Extension aia =
                    new X509AuthorityInformationAccessExtension(
                        new[] { "http://ocsp.issuer.ca.example/ocsp/" },
                        new[] { "http://issuer.ca.example/issuer.cer" });


                bool acceptSubject = true;
                string? cn = null;

                if (san is not null)
                {
                    if (req.SubjectName.RawData.Length == 2)
                    {
                        throw new InvalidOperationException("A name is required when no SAN extension is present");
                    }
                }
                else
                {
                    foreach (X500RelativeDistinguishedName rdn in req.SubjectName.EnumerateRelativeDistinguishedNames())
                    {
                        if (rdn.HasMultipleValues)
                        {
                            throw new InvalidOperationException("Multi-value RDNs are not accepted");
                        }

                        switch (rdn.SingleValueType.Value)
                        {
                            case "2.5.4.3":
                                if (cn is not null)
                                {
                                    throw new InvalidOperationException("CN was specified more than once");
                                }

                                string? cnValue = rdn.GetSingleValueValue();

                                if (string.IsNullOrEmpty(cnValue) ||
                                    cnValue.IndexOfAny(new[] { ' ', '*' }) > -1 ||
                                    !cnValue.EndsWith(".fruit.example"))
                                {
                                    throw new InvalidOperationException("CN is unauthorized");
                                }

                                cn = cnValue;
                                break;
                            default:
                                acceptSubject = false;
                                break;
                        }
                    }
                }

                if (!acceptSubject)
                {
                    if (cn is null)
                    {
                        throw new InvalidOperationException("No CN provided");
                    }

                    // Rewrite the subject name.
                    X500DistinguishedNameBuilder nameBuilder = new X500DistinguishedNameBuilder();
                    nameBuilder.AddCommonName(cn);

                    req = new CertificateRequest(
                        nameBuilder.Build(),
                        req.PublicKey,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pss);
                }
                else
                {
                    // Because of the above validation we technically know we only need to remove the SAN extension,
                    // but let's just build clean, for safety.
                    req.CertificateExtensions.Clear();
                }

                // There may be a standard order these get written in.
                // This order is mostly arbitrary, except the conditional ones went last.
                req.CertificateExtensions.Add(skid);
                req.CertificateExtensions.Add(basicConstraints);
                req.CertificateExtensions.Add(akid);
                req.CertificateExtensions.Add(cdp);
                req.CertificateExtensions.Add(aia);

                if (eku is not null)
                {
                    req.CertificateExtensions.Add(eku);
                }

                if (ku is not null)
                {
                    req.CertificateExtensions.Add(ku);
                }

                if (san is not null)
                {
                    req.CertificateExtensions.Add(san);
                }

                return req;
            }

            static byte[] BuildRequest(X500DistinguishedName reqName, string? challengePassword)
            {
                using (RSA key = RSA.Create())
                {
                    CertificateRequest req = new CertificateRequest(
                        reqName,
                        key,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

                    SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                    sanBuilder.AddDnsName("grapefruit.fruit.example");
                    sanBuilder.AddDnsName("honeydew.fruit.example");
                    sanBuilder.AddDnsName("honeydew.fruit.example");
                    sanBuilder.AddIpAddress(IPAddress.Parse("10.1.13.5"));
                    sanBuilder.AddEmailAddress("email@fruit.example");

                    req.CertificateExtensions.Add(sanBuilder.Build());

                    if (!string.IsNullOrWhiteSpace(challengePassword))
                    {
                        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
                        writer.WriteCharacterString(UniversalTagNumber.UTF8String, challengePassword.Trim());

                        req.OtherRequestAttributes.Add(
                            new AsnEncodedData("1.2.840.113549.1.9.7", writer.Encode()));
                    }

                    return req.CreateSigningRequest();
                }
            }

            static X509Certificate2 MakeCA()
            {
                using (RSA key = RSA.Create())
                {
                    CertificateRequest req = new CertificateRequest(
                        "CN=Issuing Authority",
                        key,
                        HashAlgorithmName.SHA384,
                        RSASignaturePadding.Pkcs1);

                    req.CertificateExtensions.Add(X509BasicConstraintsExtension.CreateForCertificateAuthority());
                    req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
                    req.CertificateExtensions.Add(
                        new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

                    DateTimeOffset now = DateTimeOffset.UtcNow;
                    return req.CreateSelfSigned(now.AddHours(-1), now.AddHours(1));
                }
            }
        }
    }
}
