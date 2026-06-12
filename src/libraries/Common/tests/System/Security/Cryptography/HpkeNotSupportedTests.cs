// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.Tests
{
    [ConditionalClass(typeof(HpkeNotSupportedTests), nameof(HpkeNotSupportedTests.IsNotSupported))]
    public static class HpkeNotSupportedTests
    {
        public static bool IsNotSupported => !Hpke.IsSupported;

        [Fact]
        public static void GenerateKey_NotSupported()
        {
            Assert.Throws<PlatformNotSupportedException>(() =>
                Hpke.GenerateKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM));
        }

        [Fact]
        public static void ImportEncapsulationKey_Span_NotSupported()
        {
            HpkeSuite suite = HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM;

            Assert.Throws<PlatformNotSupportedException>(() =>
                Hpke.ImportEncapsulationKey(suite, new byte[suite.EncapsulationKeySizeInBytes]));
        }

        [Fact]
        public static void ImportEncapsulationKey_Array_NotSupported()
        {
            HpkeSuite suite = HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM;

            Assert.Throws<PlatformNotSupportedException>(() =>
                Hpke.ImportEncapsulationKey(suite, (ReadOnlySpan<byte>)new byte[suite.EncapsulationKeySizeInBytes]));
        }

        [Fact]
        public static void ImportDecapsulationKey_Span_NotSupported()
        {
            HpkeSuite suite = HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM;

            Assert.Throws<PlatformNotSupportedException>(() =>
                Hpke.ImportDecapsulationKey(suite, new byte[suite.DecapsulationKeySizeInBytes]));
        }

        [Fact]
        public static void ImportDecapsulationKey_Array_NotSupported()
        {
            HpkeSuite suite = HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM;

            Assert.Throws<PlatformNotSupportedException>(() =>
                Hpke.ImportDecapsulationKey(suite, (ReadOnlySpan<byte>)new byte[suite.DecapsulationKeySizeInBytes]));
        }
    }
}
