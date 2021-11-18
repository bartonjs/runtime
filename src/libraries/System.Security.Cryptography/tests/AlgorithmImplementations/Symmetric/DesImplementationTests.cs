// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Security.Cryptography.Encryption.Des.Tests;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Symmetric
{
    public class DefaultDesImplementationTests :
        DesImplementationDriver<DefaultDesImplementationTests>,
        ISymmetricAlgorithmCapabilities<DefaultDesImplementationTests>
    {
        protected override SymmetricAlgorithm Create() => DES.Create();

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => true;
    }
    
    public class DesCryptoServiceProviderImplementationTests :
        DesImplementationDriver<DesCryptoServiceProviderImplementationTests>,
        ISymmetricAlgorithmCapabilities<DesCryptoServiceProviderImplementationTests>
    {
#pragma warning disable CS0618
        protected override SymmetricAlgorithm Create() => new DESCryptoServiceProvider();
#pragma warning restore CS0618

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => false;
    }
    
    public abstract class DesImplementationDriver<TCapabilities> : SymmetricAlgorithmTestDriver<TCapabilities>
        where TCapabilities : ISymmetricAlgorithmCapabilities<TCapabilities>
    {
        protected override IEnumerable<SymmetricKnownValueTestCase> EnumerateKnownValues()
        {
            byte[] key = { 0x74, 0x4B, 0x93, 0x3A, 0x96, 0x33, 0x61, 0xD6 };
            byte[] iv = { 0x01, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

            foreach (object[] theoryData in DesCipherOneShotTests.TestCases)
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
