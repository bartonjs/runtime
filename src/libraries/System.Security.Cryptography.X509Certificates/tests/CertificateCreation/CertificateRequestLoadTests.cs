// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.CertificateCreation
{
    public static class CertificateRequestLoadTests
    {
        [Theory]
        [InlineData(true, false)]
        [InlineData(false, false)]
        [InlineData(true, true)]
        [InlineData(false, true)]
        public static void LoadBigExponentRequest_Span(bool loadExtensions, bool oversized)
        {
            byte[] pkcs10 = TestData.BigExponentPkcs10Bytes;

            if (oversized)
            {
                Array.Resize(ref pkcs10, pkcs10.Length + 22);
            }

            CertificateRequest req = CertificateRequest.LoadSigningRequest(
                new ReadOnlySpan<byte>(pkcs10),
                HashAlgorithmName.SHA256,
                out int bytesConsumed,
                unsafeLoadCertificateExtensions: loadExtensions);

            Assert.Equal(TestData.BigExponentPkcs10Bytes.Length, bytesConsumed);
            VerifyBigExponentRequest(req, loadExtensions);
        }
        
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public static void LoadBigExponentRequest_Bytes(bool loadExtensions)
        {
            CertificateRequest req = CertificateRequest.LoadSigningRequest(
                TestData.BigExponentPkcs10Bytes,
                HashAlgorithmName.SHA256,
                unsafeLoadCertificateExtensions: loadExtensions);

            VerifyBigExponentRequest(req, loadExtensions);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public static void LoadBigExponentRequest_Bytes_Oversized(bool loadExtensions)
        {
            byte[] pkcs10 = TestData.BigExponentPkcs10Bytes;
            Array.Resize(ref pkcs10, pkcs10.Length + 2);

            Assert.Throws<CryptographicException>(
                () => CertificateRequest.LoadSigningRequest(
                    pkcs10,
                    HashAlgorithmName.SHA256,
                    unsafeLoadCertificateExtensions: loadExtensions));
        }

        [Theory]
        [InlineData(true, false)]
        [InlineData(false, false)]
        [InlineData(true, true)]
        [InlineData(false, true)]
        public static void LoadBigExponentRequest_PemString(bool loadExtensions, bool multiPem)
        {
            string pem = TestData.BigExponentPkcs10Pem;

            if (multiPem)
            {
                pem = $@"
-----BEGIN UNRELATED-----
abcd
-----END UNRELATED-----
-----BEGIN CERTIFICATE REQUEST-----
!!!!!INVALID!!!!!
-----END CERTIFICATE REQUEST-----
-----BEGIN MORE UNRELATED-----
efgh
-----END MORE UNRELATED-----
{pem}
-----BEGIN CERTIFICATE REQUEST-----
!!!!!INVALID!!!!!
-----END CERTIFICATE REQUEST-----";
            }

            CertificateRequest req = CertificateRequest.LoadSigningRequestPem(
                pem,
                HashAlgorithmName.SHA256,
                unsafeLoadCertificateExtensions: loadExtensions);

            VerifyBigExponentRequest(req, loadExtensions);
        }

        [Theory]
        [InlineData(true, false)]
        [InlineData(false, false)]
        [InlineData(true, true)]
        [InlineData(false, true)]
        public static void LoadBigExponentRequest_PemSpam(bool loadExtensions, bool multiPem)
        {
            string pem = TestData.BigExponentPkcs10Pem;

            if (multiPem)
            {
                pem = $@"
-----BEGIN UNRELATED-----
abcd
-----END UNRELATED-----
Free Floating Text
-----BEGIN CERTIFICATE REQUEST-----
!!!!!INVALID!!!!!
-----END CERTIFICATE REQUEST-----
-----BEGIN MORE UNRELATED-----
efgh
-----END MORE UNRELATED-----
More Text.
{pem}
-----BEGIN CERTIFICATE REQUEST-----
!!!!!INVALID!!!!!
-----END CERTIFICATE REQUEST-----";
            }

            CertificateRequest req = CertificateRequest.LoadSigningRequestPem(
                pem.AsSpan(),
                HashAlgorithmName.SHA256,
                unsafeLoadCertificateExtensions: loadExtensions);

            VerifyBigExponentRequest(req, loadExtensions);
        }

        private static void VerifyBigExponentRequest(CertificateRequest req, bool loadExtensions)
        {
            Assert.Equal("1.2.840.113549.1.1.1", req.PublicKey.Oid.Value);
            Assert.Equal("0500", req.PublicKey.EncodedParameters.RawData.ByteArrayToHex());
            Assert.Null(req.PublicKey.EncodedParameters.Oid);
            Assert.Null(req.PublicKey.EncodedKeyValue.Oid);

            Assert.Equal(
                "3082010C0282010100AF81C1CBD8203F624A539ED6608175372393A2837D4890" +
                    "E48A19DED36973115620968D6BE0D3DAA38AA777BE02EE0B6B93B724E8DCC12B" +
                    "632B4FA80BBC925BCE624F4CA7CC606306B39403E28C932D24DD546FFE4EF6A3" +
                    "7F10770B2215EA8CBB5BF427E8C4D89B79EB338375100C5F83E55DE9B4466DDF" +
                    "BEEE42539AEF33EF187B7760C3B1A1B2103C2D8144564A0C1039A09C85CF6B59" +
                    "74EB516FC8D6623C94AE3A5A0BB3B4C792957D432391566CF3E2A52AFB0C142B" +
                    "9E0681B8972671AF2B82DD390A39B939CF719568687E4990A63050CA7768DCD6" +
                    "B378842F18FDB1F6D9FF096BAF7BEB98DCF930D66FCFD503F58D41BFF46212E2" +
                    "4E3AFC45EA42BD884702050200000441",
                req.PublicKey.EncodedKeyValue.RawData.ByteArrayToHex());

            Assert.Equal(
                "CN=localhost, OU=.NET Framework (CoreFX), O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
                req.SubjectName.Name);

            if (loadExtensions)
            {
                Assert.Equal(1, req.CertificateExtensions.Count);

                X509SubjectAlternativeNameExtension san =
                    Assert.IsType<X509SubjectAlternativeNameExtension>(req.CertificateExtensions[0]);

                Assert.Equal(new[] { IPAddress.Loopback, IPAddress.IPv6Loopback }, san.EnumerateIPAddresses());
                Assert.Equal(new[] { "localhost" }, san.EnumerateDnsNames());
            }
            else
            {
                Assert.Empty(req.CertificateExtensions);
            }
        }

        [Theory]
        [InlineData("SHA256")]
        [InlineData("SHA384")]
        [InlineData("SHA512")]
        [InlineData("SHA1")]
        public static void VerifySignature_ECDsa(string hashAlgorithm)
        {
            HashAlgorithmName hashAlgorithmName = new HashAlgorithmName(hashAlgorithm);

            using (ECDsa key = ECDsa.Create())
            {
                CertificateRequest first = new CertificateRequest(
                    "CN=Test",
                    key,
                    hashAlgorithmName);

                byte[] pkcs10;

                if (hashAlgorithm == "SHA1")
                {
                    pkcs10 = first.CreateSigningRequest(new ECDsaSha1SignatureGenerator(key));
                }
                else
                {
                    pkcs10 = first.CreateSigningRequest();
                }

                // Assert.NoThrow
                CertificateRequest.LoadSigningRequest(pkcs10, hashAlgorithmName, out _);

                pkcs10[^1] ^= 0xFF;

                Assert.Throws<CryptographicException>(
                    () => CertificateRequest.LoadSigningRequest(pkcs10, hashAlgorithmName, out _));
            }
        }

        [Theory]
        [InlineData("SHA256")]
        [InlineData("SHA384")]
        [InlineData("SHA512")]
        [InlineData("SHA1")]
        public static void VerifySignature_RSA_PKCS1(string hashAlgorithm)
        {
            HashAlgorithmName hashAlgorithmName = new HashAlgorithmName(hashAlgorithm);

            using (RSA key = RSA.Create())
            {
                CertificateRequest first = new CertificateRequest(
                    "CN=Test",
                    key,
                    hashAlgorithmName,
                    RSASignaturePadding.Pkcs1);

                byte[] pkcs10;

                if (hashAlgorithm == "SHA1")
                {
                    pkcs10 = first.CreateSigningRequest(new RSASha1Pkcs1SignatureGenerator(key));
                }
                else
                {
                    pkcs10 = first.CreateSigningRequest();
                }

                // Assert.NoThrow
                CertificateRequest.LoadSigningRequest(pkcs10, hashAlgorithmName, out _);

                pkcs10[^1] ^= 0xFF;

                Assert.Throws<CryptographicException>(
                    () => CertificateRequest.LoadSigningRequest(pkcs10, hashAlgorithmName, out _));

                // Assert.NoThrow
                CertificateRequest.LoadSigningRequest(
                    pkcs10,
                    hashAlgorithmName,
                    out _,
                    skipSignatureValidation: true);
            }
        }

        [Theory]
        [InlineData("SHA256")]
        [InlineData("SHA384")]
        [InlineData("SHA512")]
        [InlineData("SHA1")]
        public static void VerifySignature_RSA_PSS(string hashAlgorithm)
        {
            HashAlgorithmName hashAlgorithmName = new HashAlgorithmName(hashAlgorithm);

            using (RSA key = RSA.Create())
            {
                CertificateRequest first = new CertificateRequest(
                    "CN=Test",
                    key,
                    hashAlgorithmName,
                    RSASignaturePadding.Pss);

                byte[] pkcs10;

                if (hashAlgorithm == "SHA1")
                {
                    pkcs10 = first.CreateSigningRequest(new RSASha1PssSignatureGenerator(key));
                }
                else
                {
                    pkcs10 = first.CreateSigningRequest();
                }

                // Assert.NoThrow
                CertificateRequest.LoadSigningRequest(pkcs10, hashAlgorithmName, out _);

                pkcs10[^1] ^= 0xFF;

                Assert.Throws<CryptographicException>(
                    () => CertificateRequest.LoadSigningRequest(pkcs10, hashAlgorithmName, out _));

                // Assert.NoThrow
                CertificateRequest.LoadSigningRequest(
                    pkcs10,
                    hashAlgorithmName,
                    out _,
                    skipSignatureValidation: true);
            }
        }

        [Theory]
        [InlineData("SHA256")]
        [InlineData("SHA1")]
        public static void VerifySignature_DSA(string hashAlgorithm)
        {
            HashAlgorithmName hashAlgorithmName = new HashAlgorithmName(hashAlgorithm);

            using (DSA key = DSA.Create(TestData.GetDSA1024Params()))
            {
                DSAX509SignatureGenerator generator = new DSAX509SignatureGenerator(key);
                
                CertificateRequest first = new CertificateRequest(
                    new X500DistinguishedName("CN=Test"),
                    generator.PublicKey,
                    hashAlgorithmName);

                byte[] pkcs10 = first.CreateSigningRequest(generator);

                // The inbox version doesn't support DSA
                Assert.Throws<NotSupportedException>(
                    () => CertificateRequest.LoadSigningRequest(pkcs10, hashAlgorithmName, out _));

                // Assert.NoThrow
                CertificateRequest.LoadSigningRequest(
                    pkcs10,
                    hashAlgorithmName,
                    out _,
                    skipSignatureValidation: true);
            }
        }
    }
}
