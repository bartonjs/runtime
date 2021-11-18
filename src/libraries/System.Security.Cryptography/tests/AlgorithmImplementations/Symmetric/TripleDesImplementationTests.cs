// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Security.Cryptography.Encryption.TripleDes.Tests;
using Xunit;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Symmetric
{
    public class DefaultTripleDesImplementationTests :
        TripleDesImplementationDriver<DefaultTripleDesImplementationTests>,
        ISymmetricAlgorithmCapabilities<DefaultTripleDesImplementationTests>
    {
        protected override SymmetricAlgorithm Create() => TripleDES.Create();

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => true;
    }

    [ConditionalClass(typeof(PlatformDetection), nameof(PlatformDetection.IsWindows))]
    public class TripleDesCngImplementationTests :
        TripleDesImplementationDriver<TripleDesCngImplementationTests>,
        ISymmetricAlgorithmCapabilities<TripleDesCngImplementationTests>
    {
        protected override SymmetricAlgorithm Create() => new TripleDESCng();

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => true;
    }

    public class TripleDesCryptoServiceProviderImplementationTests :
        TripleDesImplementationDriver<TripleDesCryptoServiceProviderImplementationTests>,
        ISymmetricAlgorithmCapabilities<TripleDesCryptoServiceProviderImplementationTests>
    {
#pragma warning disable CS0618
        protected override SymmetricAlgorithm Create() => new TripleDESCryptoServiceProvider();
#pragma warning restore CS0618

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => false;
    }

    public abstract class TripleDesImplementationDriver<TCapabilities> : SymmetricAlgorithmTestDriver<TCapabilities>
        where TCapabilities : ISymmetricAlgorithmCapabilities<TCapabilities>
    {
        protected override IEnumerable<SymmetricKnownValueTestCase> EnumerateKnownValues()
        {
            byte[] key =
            {
                0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
                0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
                0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xA0,
            };

            byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, };

            foreach (object[] theoryData in TripleDESCipherOneShotTests.TestCases)
            {
                yield return new SymmetricKnownValueTestCase(
                    key,
                    iv,
                    (byte[])theoryData[0],
                    (byte[])theoryData[1],
                    (CipherMode)theoryData[3],
                    (PaddingMode)theoryData[2],
                    theoryData.Length > 4 ? (int)theoryData[4] : null);
            }
        }
    }
}
