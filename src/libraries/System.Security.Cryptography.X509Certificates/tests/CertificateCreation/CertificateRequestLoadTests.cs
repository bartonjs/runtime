// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.CertificateCreation
{
    public static class CertificateRequestLoadTests
    {
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
                CertificateRequest.LoadCertificateRequest(pkcs10, hashAlgorithmName, out _);

                pkcs10[^1] ^= 0xFF;

                Assert.Throws<CryptographicException>(
                    () => CertificateRequest.LoadCertificateRequest(pkcs10, hashAlgorithmName, out _));
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
                CertificateRequest.LoadCertificateRequest(pkcs10, hashAlgorithmName, out _);

                pkcs10[^1] ^= 0xFF;

                Assert.Throws<CryptographicException>(
                    () => CertificateRequest.LoadCertificateRequest(pkcs10, hashAlgorithmName, out _));

                // Assert.NoThrow
                CertificateRequest.LoadCertificateRequest(
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
                CertificateRequest.LoadCertificateRequest(pkcs10, hashAlgorithmName, out _);

                pkcs10[^1] ^= 0xFF;

                Assert.Throws<CryptographicException>(
                    () => CertificateRequest.LoadCertificateRequest(pkcs10, hashAlgorithmName, out _));

                // Assert.NoThrow
                CertificateRequest.LoadCertificateRequest(
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
                    () => CertificateRequest.LoadCertificateRequest(pkcs10, hashAlgorithmName, out _));

                // Assert.NoThrow
                CertificateRequest.LoadCertificateRequest(
                    pkcs10,
                    hashAlgorithmName,
                    out _,
                    skipSignatureValidation: true);
            }
        }
    }
}
