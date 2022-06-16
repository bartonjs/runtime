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
        public static void BuildEmpty()
        {
            BuildRsaCertificateAndRun(
                new X509Extension[]
                {
                    X509BasicConstraintsExtension.CreateForCertificateAuthority(),
                },
                static (cert, notNow) =>
                {
                    HashAlgorithmName hashAlg = HashAlgorithmName.SHA256;
                    RSASignaturePadding pad = RSASignaturePadding.Pkcs1;
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();
                    DateTimeOffset now = new DateTimeOffset(2013, 4, 6, 7, 58, 9, TimeSpan.Zero);

                    byte[] built = builder.Build(cert, 123, now.AddMinutes(5), now, hashAlg, pad);

                    // The length of the output depends on a number of factors, but they're all stable
                    // for this test (since it doesn't use ECDSA's variable-length, non-deterministic, signature)
                    //
                    // In fact, because RSASSA-PKCS1 is a deterministic algorithm, we can check it for a fixed output.

                    byte[] expected = (
                        "3082018E3078020101300D06092A864886F70D01010B05003015311330110603" +
                        "550403130A4275696C64456D707479170D3133303430363037353830395A170D" +
                        "3133303430363038303330395AA02F302D301F0603551D2304183016801478A5" +
                        "C75D51667331D5A96924114C9B5FA00D7BCB300A0603551D14040302017B300D" +
                        "06092A864886F70D01010B0500038201010005A249671E2EE8780CBE17180493" +
                        "094A5EB576465A9B2674666B762184AD992832556B36CC8320264FE45A6B4981" +
                        "439ED9CFB87EAD10D4A95769713A0442B2D3A5FD20487DA5B33BCFBE10ED921C" +
                        "8B9896B69EA443D8D9F0AF5E0EB789361655C80EC3C7C7C84F5127C6A29C27BE" +
                        "8437CE0182BD16CF697169121C2BBFAADC4EDE17C8BB76949D25376F2739E03C" +
                        "DA0609D03C024CD5A911B342571F385B3B8A782B62C5375E1D674E43447FE2EB" +
                        "9EFFCAF71CCCECBAE600C74F6FD6CB36A87C5786603501EA43794144142E8557" +
                        "EC2EBC2F7357DB050440FD97F233441E2BE981ED6309CE7C8B1C97BCE658FCEC" +
                        "6BD63004A1D3D4EA0043783E55E7ECBCF6E6").HexToByteArray();

                    Assert.Equal(expected, built);
                });
        }

        [Fact]
        public static void BuildSingleEntry()
        {
            BuildRsaCertificateAndRun(
                new X509Extension[]
                {
                    X509BasicConstraintsExtension.CreateForCertificateAuthority(),
                },
                static (cert, notNow) =>
                {
                    HashAlgorithmName hashAlg = HashAlgorithmName.SHA256;
                    RSASignaturePadding pad = RSASignaturePadding.Pkcs1;
                    DateTimeOffset now = new DateTimeOffset(2013, 4, 6, 7, 58, 9, TimeSpan.Zero);
                    CertificateRevocationListBuilder builder = new CertificateRevocationListBuilder();

                    builder.AddEntry(
                        stackalloc byte[] { 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0C, 0x15 },
                        now.AddSeconds(-1812));

                    byte[] explicitUpdateTime = builder.Build(cert, 123, now.AddMinutes(5), now, hashAlg, pad);

                    // The length of the output depends on a number of factors, but they're all stable
                    // for this test (since it doesn't use ECDSA's variable-length, non-deterministic, signature)
                    //
                    // In fact, because RSASSA-PKCS1 is a deterministic algorithm, we can check it for a fixed output.

                    byte[] expected = (
                        "308201B230819B020101300D06092A864886F70D01010B0500301B3119301706" +
                        "0355040313104275696C6453696E676C65456E747279170D3133303430363037" +
                        "353830395A170D3133303430363038303330395A301B30190208010102030508" +
                        "0C15170D3133303430363037323735375AA02F302D301F0603551D2304183016" +
                        "801478A5C75D51667331D5A96924114C9B5FA00D7BCB300A0603551D14040302" +
                        "017B300D06092A864886F70D01010B05000382010100A9E1D03571B1E4BF7670" +
                        "EC32459A74B11482741FD973FF5040D57B133B5B6C783DC9ED105C4CF5DDE8FC" +
                        "8B767C6034253D749A834622034A669AA4C6EFDB93C82EB15B69E6DC43F05BAE" +
                        "7E9E21B0351A720C5E79F3BE65304658EBDFE196269BC285D653E7ACD97811D6" +
                        "4E08792034B47D83BF9D37851116023BDF7460C5BF1492CFA486AD7B2F277870" +
                        "82E6A3C05C0E43BB7D62B234C0E6C5BA2E0103E1CCBDAE15F9CD6DB989DED687" +
                        "0915AB164EB2FC2ADA00D4980574FC2C3C0905C1BFC9F42DBF0F800FF7F9D92C" +
                        "1F99C443EFC32593C749E18C41282E0EF232643846D204A6BC23C55605299225" +
                        "6323F7BD75DEE733C9FD011B6D3B85395422046B5573").HexToByteArray();

                    AssertExtensions.SequenceEqual(expected, explicitUpdateTime);
                });
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

        private static void BuildRsaCertificateAndRun(
            IEnumerable<X509Extension> extensions,
            Action<X509Certificate2, DateTimeOffset> action,
            [CallerMemberName] string callerName = null)
        {
            using (RSA key = RSA.Create(TestData.RsaBigExponentParams))
            {
                CertificateRequest req = new CertificateRequest(
                    $"CN=\"{callerName}\"",
                    key,
                    HashAlgorithmName.SHA384,
                    RSASignaturePadding.Pkcs1);

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
    }
}
