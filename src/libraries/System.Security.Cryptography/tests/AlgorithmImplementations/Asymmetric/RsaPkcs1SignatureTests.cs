// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Security.Cryptography.Rsa.Tests;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Asymmetric
{
    public class DefaultRsaPkcs1SignatureTests : RsaPkcs1SignatureTests
    {
        protected override RSA Create() => RSA.Create();
    }

    public class RsaCspPkcs1SignatureTests : RsaPkcs1SignatureTests
    {
        protected override RSA Create() => new RSACryptoServiceProvider();
    }

    [PlatformSpecific(TestPlatforms.Windows)]
    public class RsaCngPkcs1SignatureTests : RsaPkcs1SignatureTests
    {
        protected override RSA Create() => new RSACng();
    }

    [PlatformSpecific(PlatformSupport.OpenSSL)]
    public class RsaOpenSslPkcs1SignatureTests : RsaPkcs1SignatureTests
    {
        protected override RSA Create() => new RSAOpenSsl();
    }

    public abstract class RsaPkcs1SignatureTests : SignatureTestDriver<RSA, RsaPkcs1SignatureTests>,
        ISignatureAlgorithmCapabilities<RsaPkcs1SignatureTests>
    {
        private static readonly RSASignaturePadding s_padding = RSASignaturePadding.Pkcs1;

        public static bool HasDeterministicSignature => true;

        protected override bool VerifyDataArrayCore(
            RSA key,
            ArraySegment<byte> data,
            byte[] signature,
            HashAlgorithmName hashAlgorithm)
        {
            if (data.Offset == 0 && data.Count == data.Array?.Length)
            {
                return key.VerifyData(data.Array, signature, hashAlgorithm, s_padding);
            }

            return key.VerifyData(data.Array, data.Offset, data.Count, signature, hashAlgorithm, s_padding);
        }

        protected override bool VerifyDataSpanCore(
            RSA key,
            ArraySegment<byte> data,
            ReadOnlySpan<byte> signature,
            HashAlgorithmName hashAlgorithm)
        {
            return key.VerifyData(data.AsSpan(), signature, hashAlgorithm, s_padding);
        }

        protected override bool VerifyHashArrayCore(
            RSA key,
            byte[] hash,
            byte[] signature,
            HashAlgorithmName hashAlgorithm)
        {
            return key.VerifyHash(hash, signature, hashAlgorithm, s_padding);
        }

        protected override bool VerifyHashSpanCore(
            RSA key,
            ReadOnlySpan<byte> hash,
            ArraySegment<byte> signature,
            HashAlgorithmName hashAlgorithm)
        {
            return key.VerifyHash(hash, signature, hashAlgorithm, s_padding);
        }

        protected override IEnumerable<SignatureKnownValueTestCase<RSA>> EnumerateKnownValues()
        {
            yield return new SignatureKnownValueTestCase<RSA>(
                RsaTestKeys.RSA1032,
                TestData.HelloBytes,
                new byte[]
                {
                    0x49, 0xBC, 0x1C, 0xBE, 0x72, 0xEF, 0x83, 0x6E,
                    0x2D, 0xFA, 0xE7, 0xFA, 0xEB, 0xBC, 0xF0, 0x16,
                    0xF7, 0x2C, 0x07, 0x6D, 0x9F, 0xA6, 0x68, 0x71,
                    0xDC, 0x78, 0x9C, 0xA3, 0x42, 0x9E, 0xBB, 0xF5,
                    0x72, 0xE0, 0xAB, 0x4B, 0x4B, 0x6A, 0xE7, 0x3C,
                    0xE2, 0xC8, 0x1F, 0xA2, 0x07, 0xED, 0xD3, 0x98,
                    0xE9, 0xDF, 0x9A, 0x7A, 0x86, 0xB8, 0x06, 0xED,
                    0x97, 0x46, 0xF9, 0x8A, 0xED, 0x53, 0x1D, 0x90,
                    0xC3, 0x57, 0x7E, 0x5A, 0xE4, 0x7C, 0xEC, 0xB9,
                    0x45, 0x95, 0xAB, 0xCC, 0xBA, 0x9B, 0x2C, 0x1A,
                    0x64, 0xC2, 0x2C, 0xA0, 0x36, 0x7C, 0x56, 0xF0,
                    0x78, 0x77, 0x0B, 0x27, 0xB8, 0x1C, 0xCA, 0x7D,
                    0xD4, 0x71, 0x37, 0xBF, 0xC6, 0x4C, 0x64, 0x76,
                    0xBC, 0x8A, 0x87, 0xA0, 0x81, 0xF9, 0x4A, 0x94,
                    0x7B, 0xAA, 0x80, 0x95, 0x47, 0x51, 0xF9, 0x02,
                    0xA3, 0x44, 0x5C, 0x56, 0x60, 0xFB, 0x94, 0xA8,
                    0x52,
                },
                HashAlgorithmName.SHA1);
        }
    }
}
