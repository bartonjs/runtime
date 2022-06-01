// Licensed to the.NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.CertificateCreation
{
    public static class CrlBuilderTests
    {
        [Fact]
        public static void AddEntryArgumentValidation()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

            Assert.Throws<ArgumentNullException>("serialNumber", () => builder.AddEntry((byte[])null));
            Assert.Throws<ArgumentNullException>("serialNumber", () => builder.AddEntry((byte[])null, now));
            Assert.Throws<ArgumentNullException>("certificate", () => builder.AddEntry((X509Certificate2)null));
            Assert.Throws<ArgumentNullException>("certificate", () => builder.AddEntry((X509Certificate2)null, now));
            Assert.Throws<ArgumentException>("serialNumber", () => builder.AddEntry(Array.Empty<byte>()));
            Assert.Throws<ArgumentException>("serialNumber", () => builder.AddEntry(Array.Empty<byte>(), now));
            Assert.Throws<ArgumentException>("serialNumber", () => builder.AddEntry(ReadOnlySpan<byte>.Empty));
            Assert.Throws<ArgumentException>("serialNumber", () => builder.AddEntry(ReadOnlySpan<byte>.Empty, now));
        }

        [Fact]
        public static void BuildWithIssuerCertArgumentValidation()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset notBefore = now.AddMinutes(-5);
            DateTimeOffset notAfter = now.AddMinutes(5);
            DateTimeOffset thisUpdate = now;
            DateTimeOffset nextUpdate = now.AddMinutes(1);

            const string ParamName = "issuerCertificate";
            CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

            Assert.Throws<ArgumentNullException>(ParamName, () => builder.Build(null, 0, now));

            using (ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP384))
            {
                CertificateRequest certReq = new CertificateRequest("CN=Bad CA", key, HashAlgorithmName.SHA384);

                using (X509Certificate2 cert = certReq.CreateSelfSigned(notBefore, notAfter))
                {
                    ArgumentException ex;

                    using (X509Certificate2 pubOnly = new X509Certificate2(cert.RawDataMemory.Span))
                    {
                        ex = Assert.Throws<ArgumentException>(ParamName, () => builder.Build(pubOnly, 0, nextUpdate));
                        Assert.Contains("private key", ex.Message);

                        ex = Assert.Throws<ArgumentException>(ParamName, () => builder.Build(pubOnly, 0, nextUpdate, thisUpdate));
                        Assert.Contains("private key", ex.Message);
                    }
                    
                    ex = Assert.Throws<ArgumentException>(ParamName, () => builder.Build(cert, 0, nextUpdate));
                    Assert.Contains("Basic Constraints", ex.Message);
                    Assert.DoesNotContain("appropriate", ex.Message);

                    ex = Assert.Throws<ArgumentException>(ParamName, () => builder.Build(cert, 0, nextUpdate, thisUpdate));
                    Assert.Contains("Basic Constraints", ex.Message);
                    Assert.DoesNotContain("appropriate", ex.Message);
                }

                certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

                using (X509Certificate2 cert = certReq.CreateSelfSigned(notBefore, notAfter))
                {
                    ArgumentException ex = Assert.Throws<ArgumentException>(ParamName, () => builder.Build(cert, 0, nextUpdate));
                    Assert.Contains("Basic Constraints", ex.Message);
                    Assert.Contains("appropriate", ex.Message);

                    ex = Assert.Throws<ArgumentException>(ParamName, () => builder.Build(cert, 0, nextUpdate, thisUpdate));
                    Assert.Contains("Basic Constraints", ex.Message);
                    Assert.Contains("appropriate", ex.Message);
                }

                certReq.CertificateExtensions.Clear();
                certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                certReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));

                using (X509Certificate2 cert = certReq.CreateSelfSigned(notBefore, notAfter))
                {
                    ArgumentException ex = Assert.Throws<ArgumentException>(ParamName, () => builder.Build(cert, 0, nextUpdate));
                    Assert.Contains("Key Usage", ex.Message);
                    Assert.Contains("CrlSign", ex.Message);
                    Assert.DoesNotContain("KeyCertSign", ex.Message);

                    ex = Assert.Throws<ArgumentException>(ParamName, () => builder.Build(cert, 0, nextUpdate, thisUpdate));
                    Assert.Contains("Key Usage", ex.Message);
                    Assert.Contains("CrlSign", ex.Message);
                    Assert.DoesNotContain("KeyCertSign", ex.Message);
                }

                certReq.CertificateExtensions.RemoveAt(1);
                certReq.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

                // The certificate is acceptable now, move on to other arguments.
                using (X509Certificate2 cert = certReq.CreateSelfSigned(notBefore, notAfter))
                {
                    Assert.Throws<ArgumentOutOfRangeException>(
                        "crlNumber",
                        () => builder.Build(cert, -1, nextUpdate));

                    Assert.Throws<ArgumentOutOfRangeException>(
                        "crlNumber",
                        () => builder.Build(cert, -1, nextUpdate, thisUpdate));

                    ArgumentException ex = Assert.Throws<ArgumentException>(() => builder.Build(cert, 0, now.AddYears(-10)));
                    Assert.Null(ex.ParamName);
                    Assert.Contains("thisUpdate", ex.Message);
                    Assert.Contains("nextUpdate", ex.Message);

                    ex = Assert.Throws<ArgumentException>(() => builder.Build(cert, 0, thisUpdate, nextUpdate));
                    Assert.Null(ex.ParamName);
                    Assert.Contains("thisUpdate", ex.Message);
                    Assert.Contains("nextUpdate", ex.Message);
                }
            }
        }

        [Fact]
        public static void BuildWithGeneratorArgumentValidation()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset thisUpdate = now;
            DateTimeOffset nextUpdate = now.AddMinutes(1);

            CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

            Assert.Throws<ArgumentNullException>(
                "issuerName",
                () => builder.Build((X500DistinguishedName)null, default, 0, nextUpdate, default));
            Assert.Throws<ArgumentNullException>(
                "issuerName",
                () => builder.Build((X500DistinguishedName)null, default, 0, nextUpdate, thisUpdate, default));

            X500DistinguishedName issuerName = new X500DistinguishedName("CN=Bad CA");

            Assert.Throws<ArgumentNullException>(
                "generator",
                () => builder.Build(issuerName, default, 0, nextUpdate, default));
            Assert.Throws<ArgumentNullException>(
                "generator",
                () => builder.Build(issuerName, default, 0, nextUpdate, thisUpdate, default));

            using (ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP384))
            {
                X509SignatureGenerator generator = X509SignatureGenerator.CreateForECDsa(key);

                Assert.Throws<ArgumentOutOfRangeException>(
                    "crlNumber",
                    () => builder.Build(issuerName, generator, -1, nextUpdate, default));
                Assert.Throws<ArgumentOutOfRangeException>(
                    "crlNumber",
                    () => builder.Build(issuerName, generator, -1, nextUpdate, thisUpdate, default));

                ArgumentException ex = Assert.Throws<ArgumentException>(
                    () => builder.Build(issuerName, generator, 0, now.AddYears(-10), default));
                Assert.Null(ex.ParamName);
                Assert.Contains("thisUpdate", ex.Message);
                Assert.Contains("nextUpdate", ex.Message);

                ex = Assert.Throws<ArgumentException>(
                    () => builder.Build(issuerName, generator, 0, thisUpdate, nextUpdate, default));
                Assert.Null(ex.ParamName);
                Assert.Contains("thisUpdate", ex.Message);
                Assert.Contains("nextUpdate", ex.Message);
            }
        }
    }
}
