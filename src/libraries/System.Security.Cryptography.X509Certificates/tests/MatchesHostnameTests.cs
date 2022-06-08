// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net;
using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests
{
    public static class MatchesHostnameTests
    {
        [Theory]
        [InlineData("fruit.example", false)]
        [InlineData("127.0.0.1", false)]
        [InlineData("microsoft.com", true)]
        [InlineData("www.microsoft.com", true)]
        [InlineData("wwwqa.microsoft.com", true)]
        [InlineData("wwwqa2.microsoft.com", false)]
        [InlineData("staticview.microsoft.com", true)]
        [InlineData("c.s-microsoft.com", true)]
        [InlineData("i.s-microsoft.com", true)]
        [InlineData("j.s-microsoft.com", false)]
        [InlineData("s-microsoft.com", false)]
        [InlineData("privacy.microsoft.com", true)]
        [InlineData("more.privacy.microsoft.com", false)]
        [InlineData("moreprivacy.microsoft.com", false)]
        public static void MicrosoftDotComSslMatchesHostname(string candidate, bool expected)
        {
            using (X509Certificate2 cert = new X509Certificate2(TestData.MicrosoftDotComSslCertBytes))
            {
                AssertMatch(expected, cert, candidate);
            }
        }

        [Fact]
        public static void SanDnsMeansNoCommonNameFallback()
        {
            using (ECDsa key = ECDsa.Create())
            {
                CertificateRequest req = new CertificateRequest(
                    "CN=zalzalak.fruit.example",
                    key,
                    HashAlgorithmName.SHA256);

                SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("yumberry.fruit.example");
                sanBuilder.AddDnsName("*.pome.fruit.example");

                req.CertificateExtensions.Add(sanBuilder.Build());

                DateTimeOffset now = DateTimeOffset.UtcNow;
                DateTimeOffset notBefore = now.AddMinutes(-1);
                DateTimeOffset notAfter = now.AddMinutes(1);

                using (X509Certificate2 cert = req.CreateSelfSigned(notBefore, notAfter))
                {
                    AssertMatch(true, cert, "yumberry.fruit.example");
                    AssertMatch(true, cert, "zalzalak.pome.fruit.example");

                    // zalzalak is a pome, and our fake DNS knows that, but the certificate doesn't.
                    AssertMatch(false, cert, "zalzalak.fruit.example");
                }
            }
        }

        [Fact]
        public static void SanWithNoDnsMeansDoCommonNameFallback()
        {
            using (ECDsa key = ECDsa.Create())
            {
                CertificateRequest req = new CertificateRequest(
                    "CN=zalzalak.fruit.example",
                    key,
                    HashAlgorithmName.SHA256);

                SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddIpAddress(IPAddress.Loopback);
                sanBuilder.AddEmailAddress("it@fruit.example");

                req.CertificateExtensions.Add(sanBuilder.Build());

                DateTimeOffset now = DateTimeOffset.UtcNow;
                DateTimeOffset notBefore = now.AddMinutes(-1);
                DateTimeOffset notAfter = now.AddMinutes(1);

                using (X509Certificate2 cert = req.CreateSelfSigned(notBefore, notAfter))
                {
                    AssertMatch(false, cert, "yumberry.fruit.example");
                    AssertMatch(true, cert, "127.0.0.1");

                    // Since the SAN contains no dNSName values, we fall back to the CN.
                    AssertMatch(true, cert, "zalzalak.fruit.example");
                    AssertMatch(false, cert, "zalzalak.fruit.example", allowCommonName: false);
                }
            }
        }

        [Fact]
        public static void SanDoesNotMatchIPAddressInDnsName()
        {
            using (ECDsa key = ECDsa.Create())
            {
                CertificateRequest req = new CertificateRequest(
                    "CN=10.0.0.1",
                    key,
                    HashAlgorithmName.SHA256);

                SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("127.0.0.1");
                sanBuilder.AddEmailAddress("it@fruit.example");

                req.CertificateExtensions.Add(sanBuilder.Build());

                DateTimeOffset now = DateTimeOffset.UtcNow;
                DateTimeOffset notBefore = now.AddMinutes(-1);
                DateTimeOffset notAfter = now.AddMinutes(1);

                using (X509Certificate2 cert = req.CreateSelfSigned(notBefore, notAfter))
                {
                    // 127.0.0.1 is an IP Address, but the SAN calls it a dNSName, so it won't match.
                    AssertMatch(false, cert, "127.0.0.1");

                    // Since the SAN contains no iPAddress values, we fall back to the CN.
                    AssertMatch(true, cert, "10.0.0.1");
                }
            }
        }

        [Fact]
        public static void CommonNameDoesNotUseWildcards()
        {
            using (ECDsa key = ECDsa.Create())
            {
                CertificateRequest req = new CertificateRequest(
                    "CN=*.fruit.example",
                    key,
                    HashAlgorithmName.SHA256);

                DateTimeOffset now = DateTimeOffset.UtcNow;
                DateTimeOffset notBefore = now.AddMinutes(-1);
                DateTimeOffset notAfter = now.AddMinutes(1);

                using (X509Certificate2 cert = req.CreateSelfSigned(notBefore, notAfter))
                {
                    AssertMatch(false, cert, "papaya.fruit.example");

                    AssertMatch(true, cert, "*.fruit.example");
                }
            }
        }

        [Fact]
        public static void NoPartialWildcards()
        {
            using (ECDsa key = ECDsa.Create())
            {
                CertificateRequest req = new CertificateRequest(
                    "CN=10.0.0.1",
                    key,
                    HashAlgorithmName.SHA256);

                SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("*berry.fruit.example");
                sanBuilder.AddDnsName("cran*.fruit.example");
                sanBuilder.AddEmailAddress("it@fruit.example");

                req.CertificateExtensions.Add(sanBuilder.Build());

                DateTimeOffset now = DateTimeOffset.UtcNow;
                DateTimeOffset notBefore = now.AddMinutes(-1);
                DateTimeOffset notAfter = now.AddMinutes(1);

                using (X509Certificate2 cert = req.CreateSelfSigned(notBefore, notAfter))
                {
                    AssertMatch(false, cert, "cranberry.fruit.example");

                    // Since we don't consider the partial wildcards as wildcards, they do match unexpanded.
                    AssertMatch(true, cert, "*berry.fruit.example");
                    AssertMatch(true, cert, "cran*.fruit.example");
                }
            }
        }

        [Fact]
        public static void WildcardsDoNotMatchThroughPeriods()
        {
            using (ECDsa key = ECDsa.Create())
            {
                CertificateRequest req = new CertificateRequest(
                    "CN=10.0.0.1",
                    key,
                    HashAlgorithmName.SHA256);

                SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("fruit.example");
                sanBuilder.AddDnsName("*.fruit.example");
                sanBuilder.AddDnsName("rambutan.fruit.example");
                sanBuilder.AddEmailAddress("it@fruit.example");

                req.CertificateExtensions.Add(sanBuilder.Build());

                DateTimeOffset now = DateTimeOffset.UtcNow;
                DateTimeOffset notBefore = now.AddMinutes(-1);
                DateTimeOffset notAfter = now.AddMinutes(1);

                using (X509Certificate2 cert = req.CreateSelfSigned(notBefore, notAfter))
                {
                    AssertMatch(true, cert, "apple.fruit.example");
                    AssertMatch(true, cert, "blackberry.fruit.example");
                    AssertMatch(true, cert, "pome.fruit.example");
                    AssertMatch(true, cert, "pomme.fruit.example");
                    AssertMatch(true, cert, "rambutan.fruit.example");
                    AssertMatch(false, cert, "apple.pome.fruit.example");
                    AssertMatch(false, cert, "apple.pomme.fruit.example");

                    AssertMatch(true, cert, "*.fruit.example");
                    AssertMatch(true, cert, "*.fruit.example", allowWildcards: false);

                    AssertMatch(false, cert, "apple.fruit.example", allowWildcards: false);
                    AssertMatch(false, cert, "blackberry.fruit.example", allowWildcards: false);
                    AssertMatch(false, cert, "pome.fruit.example", allowWildcards: false);
                    AssertMatch(false, cert, "pomme.fruit.example", allowWildcards: false);
                    // This one has a redundant dNSName after the wildcard
                    AssertMatch(true, cert, "rambutan.fruit.example", allowWildcards: false);

                    AssertMatch(true, cert, "fruit.example");
                    AssertMatch(true, cert, "fruit.example", allowWildcards: false);
                }
            }
        }

        [Theory]
        [InlineData("aPPlE.fruit.example", true)]
        [InlineData("tOmaTO.FRUIT.example", true)]
        [InlineData("tOmaTO.vegetable.example", false)]
        [InlineData("FRUit.example", true)]
        [InlineData("VEGetaBlE.example", false)]
        public static void DnsMatchNotCaseSensitive(string target, bool expected)
        {
            using (ECDsa key = ECDsa.Create())
            {
                CertificateRequest req = new CertificateRequest(
                    "CN=10.0.0.1",
                    key,
                    HashAlgorithmName.SHA256);

                SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("fruit.EXAMPLE");
                sanBuilder.AddDnsName("*.FrUIt.eXaMpLE");
                sanBuilder.AddEmailAddress("it@fruit.example");

                req.CertificateExtensions.Add(sanBuilder.Build());

                DateTimeOffset now = DateTimeOffset.UtcNow;
                DateTimeOffset notBefore = now.AddMinutes(-1);
                DateTimeOffset notAfter = now.AddMinutes(1);

                using (X509Certificate2 cert = req.CreateSelfSigned(notBefore, notAfter))
                {
                    AssertMatch(expected, cert, target);
                }
            }
        }

        private static void AssertMatch(
            bool expected,
            X509Certificate2 cert,
            string hostname,
            bool allowWildcards = true,
            bool allowCommonName = true)
        {
            bool match = cert.MatchesHostname(hostname, allowWildcards, allowCommonName);

            if (match != expected)
            {
                string display = $"Matches {(hostname.Contains('*') ? "(literal) " : "")}'{hostname}'";

                if (!allowWildcards && !allowCommonName)
                {
                    display += " with no wildcards or common name fallback";
                }
                else if (!allowWildcards)
                {
                    display += " with no wildcards";
                }
                else if (!allowCommonName)
                {
                    display += " with no common name fallback";
                }

                if (expected)
                {
                    Assert.True(match, display);
                }
                else
                {
                    Assert.False(match, display);
                }
            }
        }
    }
}
