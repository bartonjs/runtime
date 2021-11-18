// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Security.Cryptography.Encryption.RC2.Tests;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Symmetric
{
    public class DefaultRC2ImplementationTests :
        RC2ImplementationDriver<DefaultRC2ImplementationTests>,
        ISymmetricAlgorithmCapabilities<DefaultRC2ImplementationTests>
    {
        protected override SymmetricAlgorithm Create() => RC2.Create();

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => true;
    }

    public class RC2CryptoServiceProviderImplementationTests :
        RC2ImplementationDriver<RC2CryptoServiceProviderImplementationTests>,
        ISymmetricAlgorithmCapabilities<RC2CryptoServiceProviderImplementationTests>
    {
#pragma warning disable CS0618
        protected override SymmetricAlgorithm Create() => new RC2CryptoServiceProvider();
#pragma warning restore CS0618

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => false;
    }

    public abstract class RC2ImplementationDriver<TCapabilities> : SymmetricAlgorithmTestDriver<TCapabilities>
        where TCapabilities : ISymmetricAlgorithmCapabilities<TCapabilities>
    {
        protected override IEnumerable<SymmetricKnownValueTestCase> EnumerateKnownValues()
        {
            byte[] key = { 0x83, 0x2F, 0x81, 0x1B, 0x61, 0x02, 0xCC, 0x8F, 0x2F, 0x78, 0x10, 0x68, 0x06, 0xA6, 0x35, 0x50, };
            byte[] iv = { 0x01, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

            foreach (object[] theoryData in RC2CipherOneShotTests.TestCases)
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
