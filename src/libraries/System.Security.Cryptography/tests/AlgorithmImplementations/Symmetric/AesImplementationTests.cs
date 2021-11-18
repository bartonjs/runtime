// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Security.Cryptography.Encryption.Aes.Tests;
using Xunit;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Symmetric
{
    public class DefaultAesImplementationTests :
        AesImplementationDriver<DefaultAesImplementationTests>,
        ISymmetricAlgorithmCapabilities<DefaultAesImplementationTests>
    {
        protected override SymmetricAlgorithm Create() => Aes.Create();

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => true;
    }

    [ConditionalClass(typeof(PlatformDetection), nameof(PlatformDetection.IsWindows))]
    public class AesCngImplementationTests :
        AesImplementationDriver<AesCngImplementationTests>,
        ISymmetricAlgorithmCapabilities<AesCngImplementationTests>
    {
        protected override SymmetricAlgorithm Create() => new AesCng();

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => true;
    }

    public class AesCryptoServiceProviderImplementationTests :
        AesImplementationDriver<AesCryptoServiceProviderImplementationTests>,
        ISymmetricAlgorithmCapabilities<AesCryptoServiceProviderImplementationTests>
    {
#pragma warning disable CS0618
        protected override SymmetricAlgorithm Create() => new AesCryptoServiceProvider();
#pragma warning restore CS0618

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => false;
    }

    public class AesManagedImplementationTests :
        AesImplementationDriver<AesManagedImplementationTests>,
        ISymmetricAlgorithmCapabilities<AesManagedImplementationTests>
    {
#pragma warning disable CS0618
        protected override SymmetricAlgorithm Create() => new AesManaged();
#pragma warning restore CS0618

        public static bool CanReadKeyProperty => true;
        public static bool HasOneShots => false;
    }

    public abstract class AesImplementationDriver<TCapabilities> : SymmetricAlgorithmTestDriver<TCapabilities>
        where TCapabilities : ISymmetricAlgorithmCapabilities<TCapabilities>
    {
        protected override IEnumerable<SymmetricKnownValueTestCase> EnumerateKnownValues()
        {
            byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12 };
            byte[] iv = { 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22 };

            foreach (object[] theoryData in AesCipherOneShotTests.TestCases)
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
