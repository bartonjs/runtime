// Licensed to the.NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.CertificateCreation
{
    public static class CrlBuilderTests
    {
        private const string CertParam = "issuerCertificate";

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
        public static void BuildWithNullCertificate()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

            Assert.Throws<ArgumentNullException>(CertParam, () => builder.Build(null, 0, now, HashAlgorithmName.SHA256));
            Assert.Throws<ArgumentNullException>(CertParam, () => builder.Build(null, 0, now, now, HashAlgorithmName.SHA256));
        }

        [Fact]
        public static void BuildWithNoPrivateKeyCertificate()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

            using (X509Certificate2 cert = new X509Certificate2(TestData.MsCertificatePemBytes))
            {
                ArgumentException e;

                e = Assert.Throws<ArgumentException>(
                    CertParam,
                    () => builder.Build(cert, 0, now, HashAlgorithmName.SHA256));

                Assert.Contains("private key", e.Message);

                e = Assert.Throws<ArgumentException>(
                    CertParam,
                    () => builder.Build(cert, 0, now, now, HashAlgorithmName.SHA256));

                Assert.Contains("private key", e.Message);
            }
        }

        [Fact]
        public static void BuildWithCertificateWithNoBasicConstraints()
        {
            BuildCertificateAndRun(
                Enumerable.Empty<X509Extension>(),
                static (cert, now) =>
                {
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

                    ArgumentException e;

                    e = Assert.Throws<ArgumentException>(
                        CertParam,
                        () => builder.Build(cert, 0, now.AddMinutes(5), HashAlgorithmName.SHA256));

                    Assert.Contains("Basic Constraints", e.Message);
                    Assert.DoesNotContain("appropriate", e.Message);

                    e = Assert.Throws<ArgumentException>(
                        CertParam,
                        () => builder.Build(cert, 0, now.AddMinutes(5), now, HashAlgorithmName.SHA256));

                    Assert.Contains("Basic Constraints", e.Message);
                    Assert.DoesNotContain("appropriate", e.Message);
                });
        }

        [Fact]
        public static void BuildWithCertificateWithBadBasicConstraints()
        {
            BuildCertificateAndRun(
                new X509Extension[]
                {
                    X509BasicConstraintsExtension.CreateForEndEntity(),
                },
                static (cert, now) =>
                {
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

                    ArgumentException e;

                    e = Assert.Throws<ArgumentException>(
                        CertParam,
                        () => builder.Build(cert, 0, now.AddMinutes(5), HashAlgorithmName.SHA256));

                    Assert.Contains("Basic Constraints", e.Message);
                    Assert.Contains("appropriate", e.Message);

                    e = Assert.Throws<ArgumentException>(
                        CertParam,
                        () => builder.Build(cert, 0, now.AddMinutes(5), now, HashAlgorithmName.SHA256));

                    Assert.Contains("Basic Constraints", e.Message);
                    Assert.Contains("appropriate", e.Message);
                });
        }

        private static void BuildCertificateAndRun(
            IEnumerable<X509Extension> extensions,
            Action<X509Certificate2, DateTimeOffset> action,
            [CallerMemberName] string callerName = null)
        {
            using (ECDsa key = ECDsa.Create())
            {
                CertificateRequest req = new CertificateRequest(
                    $"CN=\"{callerName}\"",
                    key,
                    HashAlgorithmName.SHA384);

                foreach (X509Extension ext in extensions)
                {
                    req.CertificateExtensions.Add(ext);
                }

                DateTimeOffset now = DateTimeOffset.UtcNow;

                using (X509Certificate2 cert = req.CreateSelfSigned(now.AddMonths(-1), now.AddMonths(1)))
                {
                    action(cert, now);
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
                () => builder.Build((X500DistinguishedName)null, default, 0, nextUpdate, default, default));
            Assert.Throws<ArgumentNullException>(
                "issuerName",
                () => builder.Build((X500DistinguishedName)null, default, 0, nextUpdate, thisUpdate, default, default));

            X500DistinguishedName issuerName = new X500DistinguishedName("CN=Bad CA");

            Assert.Throws<ArgumentNullException>(
                "generator",
                () => builder.Build(issuerName, default, 0, nextUpdate, default, default));
            Assert.Throws<ArgumentNullException>(
                "generator",
                () => builder.Build(issuerName, default, 0, nextUpdate, thisUpdate, default, default));

            using (ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP384))
            {
                X509SignatureGenerator generator = X509SignatureGenerator.CreateForECDsa(key);

                Assert.Throws<ArgumentOutOfRangeException>(
                    "crlNumber",
                    () => builder.Build(issuerName, generator, -1, nextUpdate, default, default));
                Assert.Throws<ArgumentOutOfRangeException>(
                    "crlNumber",
                    () => builder.Build(issuerName, generator, -1, nextUpdate, thisUpdate, default, default));

                ArgumentException ex = Assert.Throws<ArgumentException>(
                    () => builder.Build(issuerName, generator, 0, now.AddYears(-10), default, default));
                Assert.Null(ex.ParamName);
                Assert.Contains("thisUpdate", ex.Message);
                Assert.Contains("nextUpdate", ex.Message);

                ex = Assert.Throws<ArgumentException>(
                    () => builder.Build(issuerName, generator, 0, thisUpdate, nextUpdate, default, default));
                Assert.Null(ex.ParamName);
                Assert.Contains("thisUpdate", ex.Message);
                Assert.Contains("nextUpdate", ex.Message);
            }
        }

        [Fact]
        public static void BuildSimpleCdp()
        {
            X509Extension ext = CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(
                new[] { "http://crl.microsoft.com/pki/crl/products/MicCodSigPCA_08-31-2010.crl" });

            byte[] expected = (
                "304d304ba049a0478645687474703a2f2f63726c2e6d6963726f736f" +
                "66742e636f6d2f706b692f63726c2f70726f64756374732f4d696343" +
                "6f645369675043415f30382d33312d323031302e63726c").HexToByteArray();

            Assert.Equal(expected, ext.RawData);
        }
    }
}
