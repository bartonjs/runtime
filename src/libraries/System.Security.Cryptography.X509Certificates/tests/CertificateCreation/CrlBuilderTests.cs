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

        [Fact]
        public static void BuildWithCertificateWithBadKeyUsage()
        {
            BuildCertificateAndRun(
                new X509Extension[]
                {
                    X509BasicConstraintsExtension.CreateForCertificateAuthority(),
                    new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true),
                },
                static (cert, now) =>
                {
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

                    ArgumentException e;

                    e = Assert.Throws<ArgumentException>(
                        CertParam,
                        () => builder.Build(cert, 0, now.AddMinutes(5), HashAlgorithmName.SHA256));

                    Assert.Contains("CrlSign", e.Message);

                    e = Assert.Throws<ArgumentException>(
                        CertParam,
                        () => builder.Build(cert, 0, now.AddMinutes(5), now, HashAlgorithmName.SHA256));

                    Assert.Contains("CrlSign", e.Message);
                });
        }

        [Fact]
        public static void BuildWithNextUpdateBeforeThisUpdate()
        {
            BuildCertificateAndRun(
                new X509Extension[]
                {
                    X509BasicConstraintsExtension.CreateForCertificateAuthority(),
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                        true),
                },
                static (cert, now) =>
                {
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();
                    ArgumentException e;

                    e = Assert.Throws<ArgumentException>(
                        () => builder.Build(cert, 0, now.AddMinutes(-5), HashAlgorithmName.SHA256));

                    Assert.Null(e.ParamName);
                    Assert.Contains("thisUpdate", e.Message);
                    Assert.Contains("nextUpdate", e.Message);

                    e = Assert.Throws<ArgumentException>(
                        () => builder.Build(cert, 0, now, now.AddSeconds(1), HashAlgorithmName.SHA256));

                    Assert.Null(e.ParamName);
                    Assert.Contains("thisUpdate", e.Message);
                    Assert.Contains("nextUpdate", e.Message);

                    using (ECDsa key = cert.GetECDsaPrivateKey())
                    {
                        X509SignatureGenerator gen = X509SignatureGenerator.CreateForECDsa(key);
                        X500DistinguishedName dn = cert.SubjectName;

                        e = Assert.Throws<ArgumentException>(
                            () => builder.Build(dn, gen, 0, now.AddMinutes(-5), HashAlgorithmName.SHA256, null));

                        Assert.Null(e.ParamName);
                        Assert.Contains("thisUpdate", e.Message);
                        Assert.Contains("nextUpdate", e.Message);

                        e = Assert.Throws<ArgumentException>(
                            () => builder.Build(dn, gen, 0, now, now.AddSeconds(1), HashAlgorithmName.SHA256, null));

                        Assert.Null(e.ParamName);
                        Assert.Contains("thisUpdate", e.Message);
                        Assert.Contains("nextUpdate", e.Message);
                    }
                });
        }

        [Fact]
        public static void BuildWithNoHashAlgorithm()
        {
            BuildCertificateAndRun(
                new X509Extension[]
                {
                    X509BasicConstraintsExtension.CreateForCertificateAuthority(),
                },
                static (cert, now) =>
                {
                    HashAlgorithmName hashAlg = default;
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

                    Assert.Throws<ArgumentNullException>(
                        "hashAlgorithm",
                        () => builder.Build(cert, 0, now.AddMinutes(5), hashAlg));

                    Assert.Throws<ArgumentNullException>(
                        "hashAlgorithm",
                        () => builder.Build(cert, 0, now.AddMinutes(5), now, hashAlg));

                    using (ECDsa key = cert.GetECDsaPrivateKey())
                    {
                        X509SignatureGenerator gen = X509SignatureGenerator.CreateForECDsa(key);
                        X500DistinguishedName dn = cert.SubjectName;

                        Assert.Throws<ArgumentNullException>(
                            "hashAlgorithm",
                            () => builder.Build(dn, gen, 0, now.AddMinutes(5), hashAlg, null));

                        Assert.Throws<ArgumentNullException>(
                            "hashAlgorithm",
                            () => builder.Build(dn, gen, 0, now.AddMinutes(5), now, hashAlg, null));
                    }
                });
        }

        [Fact]
        public static void BuildWithEmptyHashAlgorithm()
        {
            BuildCertificateAndRun(
                new X509Extension[]
                {
                    X509BasicConstraintsExtension.CreateForCertificateAuthority(),
                },
                static (cert, now) =>
                {
                    HashAlgorithmName hashAlg = new HashAlgorithmName("");
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();
                    ArgumentException e;

                    e = Assert.Throws<ArgumentException>(
                        "hashAlgorithm",
                        () => builder.Build(cert, 0, now.AddMinutes(5), hashAlg));

                    Assert.Contains("empty", e.Message);

                    e = Assert.Throws<ArgumentException>(
                        "hashAlgorithm",
                        () => builder.Build(cert, 0, now.AddMinutes(5), now, hashAlg));

                    Assert.Contains("empty", e.Message);

                    using (ECDsa key = cert.GetECDsaPrivateKey())
                    {
                        X509SignatureGenerator gen = X509SignatureGenerator.CreateForECDsa(key);
                        X500DistinguishedName dn = cert.SubjectName;

                        e = Assert.Throws<ArgumentException>(
                            "hashAlgorithm",
                            () => builder.Build(dn, gen, 0, now.AddMinutes(5), hashAlg, null));

                        Assert.Contains("empty", e.Message);

                        e = Assert.Throws<ArgumentException>(
                            "hashAlgorithm",
                            () => builder.Build(dn, gen, 0, now.AddMinutes(5), now, hashAlg, null));

                        Assert.Contains("empty", e.Message);
                    }
                });
        }

        [Fact]
        public static void BuildWithNegativeCrlNumber()
        {
            BuildCertificateAndRun(
                new X509Extension[]
                {
                    X509BasicConstraintsExtension.CreateForCertificateAuthority(),
                },
                static (cert, now) =>
                {
                    HashAlgorithmName hashAlg = new HashAlgorithmName("");
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

                    Assert.Throws<ArgumentOutOfRangeException>(
                        "crlNumber",
                        () => builder.Build(cert, -1, now.AddMinutes(5), hashAlg));

                    Assert.Throws<ArgumentOutOfRangeException>(
                        "crlNumber",
                        () => builder.Build(cert, -1, now.AddMinutes(5), now, hashAlg));

                    using (ECDsa key = cert.GetECDsaPrivateKey())
                    {
                        X509SignatureGenerator gen = X509SignatureGenerator.CreateForECDsa(key);
                        X500DistinguishedName dn = cert.SubjectName;

                        Assert.Throws<ArgumentOutOfRangeException>(
                            "crlNumber",
                            () => builder.Build(dn, gen, -1, now.AddMinutes(5), hashAlg, null));

                        Assert.Throws<ArgumentOutOfRangeException>(
                            "crlNumber",
                            () => builder.Build(dn, gen, -1, now.AddMinutes(5), now, hashAlg, null));
                    }
                });
        }

        [Fact]
        public static void BuildWithGeneratorNullName()
        {
            CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();
            DateTimeOffset now = DateTimeOffset.UtcNow;

            Assert.Throws<ArgumentNullException>(
                "issuerName",
                () => builder.Build(null, null, 0, now.AddMinutes(5), HashAlgorithmName.SHA256, null));

            Assert.Throws<ArgumentNullException>(
                "issuerName",
                () => builder.Build(null, null, 0, now.AddMinutes(5), now, HashAlgorithmName.SHA256, null));
        }

        [Fact]
        public static void BuildWithGeneratorNullGenerator()
        {
            CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();
            DateTimeOffset now = DateTimeOffset.UtcNow;
            X500DistinguishedName dn = new X500DistinguishedName("CN=Name");

            Assert.Throws<ArgumentNullException>(
                "generator",
                () => builder.Build(dn, null, 0, now.AddMinutes(5), HashAlgorithmName.SHA256, null));

            Assert.Throws<ArgumentNullException>(
                "generator",
                () => builder.Build(dn, null, 0, now.AddMinutes(5), now, HashAlgorithmName.SHA256, null));
        }

        [Fact]
        public static void BuildWithGeneratorNullAkid()
        {
            CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();
            DateTimeOffset now = DateTimeOffset.UtcNow;
            X500DistinguishedName dn = new X500DistinguishedName("CN=Name");

            using (RSA rsa = RSA.Create(TestData.RsaBigExponentParams))
            {
                X509SignatureGenerator gen = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);

                Assert.Throws<ArgumentNullException>(
                    "akid",
                    () => builder.Build(dn, gen, 0, now.AddMinutes(5), HashAlgorithmName.SHA256, null));

                Assert.Throws<ArgumentNullException>(
                    "akid",
                    () => builder.Build(dn, gen, 0, now.AddMinutes(5), now, HashAlgorithmName.SHA256, null));
            }
        }

        [Fact]
        public static void BuildWithRSACertificateAndNoPadding()
        {
            using (RSA key = RSA.Create(TestData.RsaBigExponentParams))
            {
                CertificateRequest req = new CertificateRequest(
                    "CN=RSA Test",
                    key,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
                req.CertificateExtensions.Add(X509BasicConstraintsExtension.CreateForCertificateAuthority());

                DateTimeOffset now = DateTimeOffset.UtcNow;

                using (X509Certificate2 cert = req.CreateSelfSigned(now.AddMonths(-1), now.AddMonths(1)))
                {
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();
                    ArgumentException e;

                    e = Assert.Throws<ArgumentException>(
                        () => builder.Build(cert, 0, now.AddMinutes(5), HashAlgorithmName.SHA256));

                    Assert.Null(e.ParamName);
                    Assert.Contains(nameof(RSASignaturePadding), e.Message);

                    e = Assert.Throws<ArgumentException>(
                        () => builder.Build(cert, 0, now.AddMinutes(5), now, HashAlgorithmName.SHA256));

                    Assert.Null(e.ParamName);
                    Assert.Contains(nameof(RSASignaturePadding), e.Message);
                }
            }
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

                req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

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
