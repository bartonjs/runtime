// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Linq;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Asymmetric
{
    public abstract class SignatureTestDriver
    {
        public enum SignMode
        {
            SignDataArray,
            SignDataSpan,
            SignDataTrySpan,
            SignHashArray,
            SignHashSpan,
            SignHashTrySpan,
        }

        public enum VerifyMode
        {
            VerifyDataArray,
            VerifyDataSpan,
            VerifyHashArray,
            VerifyHashSpan,
        }

        public static IEnumerable<object[]> SignAndVerifyModes { get; } =
            new[]
            {
                new object[] { SignMode.SignDataArray, VerifyMode.VerifyHashSpan },
                new object[] { SignMode.SignDataSpan, VerifyMode.VerifyDataSpan },
                new object[] { SignMode.SignDataTrySpan, VerifyMode.VerifyDataArray },
                new object[] { SignMode.SignHashArray, VerifyMode.VerifyHashArray },
                new object[] { SignMode.SignHashSpan, VerifyMode.VerifyHashSpan },
                new object[] { SignMode.SignHashTrySpan, VerifyMode.VerifyDataSpan },
            };

        public static IEnumerable<object[]> VerifyModes { get; } =
            Enum.GetValues<VerifyMode>().Select(v => new object[] { v }).ToArray();

        // ASCII/UTF-8 of
        // This is a sentence that is longer than a block, it ensures that multi-block functions work.
        private static ReadOnlySpan<byte> Input0Span => new byte[]
        {
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
            0x61, 0x20, 0x73, 0x65, 0x6E, 0x74, 0x65, 0x6E,
            0x63, 0x65, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20,
            0x69, 0x73, 0x20, 0x6C, 0x6F, 0x6E, 0x67, 0x65,
            0x72, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x61,
            0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x2C, 0x20,
            0x69, 0x74, 0x20, 0x65, 0x6E, 0x73, 0x75, 0x72,
            0x65, 0x73, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20,
            0x6D, 0x75, 0x6C, 0x74, 0x69, 0x2D, 0x62, 0x6C,
            0x6F, 0x63, 0x6B, 0x20, 0x66, 0x75, 0x6E, 0x63,
            0x74, 0x69, 0x6F, 0x6E, 0x73, 0x20, 0x77, 0x6F,
            0x72, 0x6B, 0x2E,
        };
    }

    public abstract partial class SignatureTestDriver<TAlgorithm, TCapabilities> : SignatureTestDriver
        where TAlgorithm : AsymmetricAlgorithm
        where TCapabilities : ISignatureAlgorithmCapabilities<TCapabilities>
    {
        protected abstract TAlgorithm Create();
        protected abstract IEnumerable<SignatureKnownValueTestCase<TAlgorithm>> EnumerateKnownValues();

        private bool Verify(
            TAlgorithm key,
            ArraySegment<byte> data,
            byte[] hash,
            byte[] signature,
            HashAlgorithmName hashAlgorithm,
            VerifyMode testMode)
        {
            switch (testMode)
            {
                case VerifyMode.VerifyDataArray:
                    return VerifyDataArrayCore(key, data, signature, hashAlgorithm);
                case VerifyMode.VerifyDataSpan:
                    return VerifyDataSpanCore(key, data, signature, hashAlgorithm);
                case VerifyMode.VerifyHashArray:
                    return VerifyHashArrayCore(key, hash, signature, hashAlgorithm);
                case VerifyMode.VerifyHashSpan:
                    return VerifyHashSpanCore(key, hash, signature, hashAlgorithm);
                default:
                    throw new ArgumentOutOfRangeException(
                        nameof(testMode),
                        testMode,
                        $"'{testMode}' is not a handled encryption mode");
            }
        }

        protected abstract bool VerifyDataArrayCore(
            TAlgorithm key,
            ArraySegment<byte> data,
            byte[] signature,
            HashAlgorithmName hashAlgorithm);

        protected abstract bool VerifyDataSpanCore(
            TAlgorithm key,
            ArraySegment<byte> data,
            ReadOnlySpan<byte> signature,
            HashAlgorithmName hashAlgorithm);

        protected abstract bool VerifyHashArrayCore(
            TAlgorithm key,
            byte[] hash,
            byte[] signature,
            HashAlgorithmName hashAlgorithm);

        protected abstract bool VerifyHashSpanCore(
            TAlgorithm key,
            ReadOnlySpan<byte> hash,
            ArraySegment<byte> signature,
            HashAlgorithmName hashAlgorithm);
    }
}
