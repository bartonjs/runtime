// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.Tests
{
    public static class HpkeSuiteTests
    {
        [Fact]
        public static void Suites_AreSame()
        {
            Assert.Same(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            Assert.Same(HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM, HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM);
            Assert.Same(HpkeSuite.DHKEM_X25519_HKDF_SHA256_AES_128_GCM, HpkeSuite.DHKEM_X25519_HKDF_SHA256_AES_128_GCM);
            Assert.Same(HpkeSuite.DHKEM_X25519_HKDF_SHA256_ChaCha20Poly1305, HpkeSuite.DHKEM_X25519_HKDF_SHA256_ChaCha20Poly1305);
        }

        [Fact]
        public static void Suites_AreEqual()
        {
            Assert.Equal(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            Assert.Equal(HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM, HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM);
        }

        [Fact]
        public static void Suites_AreNotEqual_Across()
        {
            Assert.NotEqual(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM);
            Assert.NotEqual(HpkeSuite.DHKEM_X25519_HKDF_SHA256_AES_128_GCM, HpkeSuite.DHKEM_X25519_HKDF_SHA256_ChaCha20Poly1305);
        }

        [Fact]
        public static void Suites_EqualOperators()
        {
            Assert.True(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM == HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            Assert.False(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM != HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            Assert.False(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM == HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM);
            Assert.True(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM != HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM);
        }

        [Fact]
        public static void Suites_NullEquality()
        {
            HpkeSuite? left = null;
            Assert.True(left == null);
            Assert.False(left != null);
            Assert.False(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM == null);
            Assert.True(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM != null);
            Assert.False(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM.Equals(null));
            Assert.False(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM.Equals((object?)null));
        }

        [Fact]
        public static void Suites_GetHashCode_EqualForEqualSuites()
        {
            Assert.Equal(
                HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM.GetHashCode(),
                HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM.GetHashCode());
        }

        [Fact]
        public static void Suites_ToString_ReturnsName()
        {
            Assert.Contains("P-256", HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM.ToString());
            Assert.Contains("P-384", HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM.ToString());
            Assert.Contains("X25519", HpkeSuite.DHKEM_X25519_HKDF_SHA256_AES_128_GCM.ToString());
            Assert.Contains("ChaCha20", HpkeSuite.DHKEM_X25519_HKDF_SHA256_ChaCha20Poly1305.ToString());
        }

        [Theory]
        [InlineData(65, 32, 65, 16)]
        public static void P256Suite_Sizes(int encapKey, int decapKey, int encapsulated, int aeadTag)
        {
            HpkeSuite suite = HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM;
            Assert.Equal(encapKey, suite.EncapsulationKeySizeInBytes);
            Assert.Equal(decapKey, suite.DecapsulationKeySizeInBytes);
            Assert.Equal(encapsulated, suite.EncapsulatedKeySizeInBytes);
            Assert.Equal(aeadTag, suite.AeadTagSizeInBytes);
        }

        [Theory]
        [InlineData(97, 48, 97, 16)]
        public static void P384Suite_Sizes(int encapKey, int decapKey, int encapsulated, int aeadTag)
        {
            HpkeSuite suite = HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM;
            Assert.Equal(encapKey, suite.EncapsulationKeySizeInBytes);
            Assert.Equal(decapKey, suite.DecapsulationKeySizeInBytes);
            Assert.Equal(encapsulated, suite.EncapsulatedKeySizeInBytes);
            Assert.Equal(aeadTag, suite.AeadTagSizeInBytes);
        }

        [Theory]
        [InlineData(32, 32, 32, 16)]
        public static void X25519AesSuite_Sizes(int encapKey, int decapKey, int encapsulated, int aeadTag)
        {
            HpkeSuite suite = HpkeSuite.DHKEM_X25519_HKDF_SHA256_AES_128_GCM;
            Assert.Equal(encapKey, suite.EncapsulationKeySizeInBytes);
            Assert.Equal(decapKey, suite.DecapsulationKeySizeInBytes);
            Assert.Equal(encapsulated, suite.EncapsulatedKeySizeInBytes);
            Assert.Equal(aeadTag, suite.AeadTagSizeInBytes);
        }

        [Fact]
        public static void WellKnownSuite_P256_HasCorrectAlgorithms()
        {
            HpkeSuite suite = HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM;
            Assert.Equal(HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256, suite.KemAlgorithm);
            Assert.Equal(HpkeSuite.Kdf.HKDF_SHA256, suite.KdfAlgorithm);
            Assert.Equal(HpkeSuite.Aead.Aes128Gcm, suite.AeadAlgorithm);
        }

        [Fact]
        public static void WellKnownSuite_P384_HasCorrectAlgorithms()
        {
            HpkeSuite suite = HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM;
            Assert.Equal(HpkeSuite.Kem.DHKEM_P384_HKDF_SHA384, suite.KemAlgorithm);
            Assert.Equal(HpkeSuite.Kdf.HKDF_SHA384, suite.KdfAlgorithm);
            Assert.Equal(HpkeSuite.Aead.Aes256Gcm, suite.AeadAlgorithm);
        }

        [Fact]
        public static void WellKnownSuite_X25519Aes_HasCorrectAlgorithms()
        {
            HpkeSuite suite = HpkeSuite.DHKEM_X25519_HKDF_SHA256_AES_128_GCM;
            Assert.Equal(HpkeSuite.Kem.DHKEM_X25519_HKDF_SHA256, suite.KemAlgorithm);
            Assert.Equal(HpkeSuite.Kdf.HKDF_SHA256, suite.KdfAlgorithm);
            Assert.Equal(HpkeSuite.Aead.Aes128Gcm, suite.AeadAlgorithm);
        }

        [Fact]
        public static void WellKnownSuite_X25519ChaCha_HasCorrectAlgorithms()
        {
            HpkeSuite suite = HpkeSuite.DHKEM_X25519_HKDF_SHA256_ChaCha20Poly1305;
            Assert.Equal(HpkeSuite.Kem.DHKEM_X25519_HKDF_SHA256, suite.KemAlgorithm);
            Assert.Equal(HpkeSuite.Kdf.HKDF_SHA256, suite.KdfAlgorithm);
            Assert.Equal(HpkeSuite.Aead.ChaCha20Poly1305, suite.AeadAlgorithm);
        }

        [Theory]
        [InlineData(HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256, HpkeSuite.Kdf.HKDF_SHA256, HpkeSuite.Aead.Aes128Gcm)]
        [InlineData(HpkeSuite.Kem.DHKEM_P384_HKDF_SHA384, HpkeSuite.Kdf.HKDF_SHA384, HpkeSuite.Aead.Aes256Gcm)]
        [InlineData(HpkeSuite.Kem.DHKEM_X25519_HKDF_SHA256, HpkeSuite.Kdf.HKDF_SHA256, HpkeSuite.Aead.ChaCha20Poly1305)]
        public static void ComposedSuite_EqualsWellKnown(HpkeSuite.Kem kem, HpkeSuite.Kdf kdf, HpkeSuite.Aead aead)
        {
            HpkeSuite composed = new HpkeSuite(kem, kdf, aead);
            HpkeSuite wellKnown = kem switch
            {
                HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256 => HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM,
                HpkeSuite.Kem.DHKEM_P384_HKDF_SHA384 => HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM,
                HpkeSuite.Kem.DHKEM_X25519_HKDF_SHA256 => HpkeSuite.DHKEM_X25519_HKDF_SHA256_ChaCha20Poly1305,
                _ => throw new InvalidOperationException(),
            };

            Assert.Equal(wellKnown, composed);
            Assert.Equal(wellKnown.GetHashCode(), composed.GetHashCode());
        }

        [Fact]
        public static void ComposedSuite_NonStandardCombination_HasCorrectProperties()
        {
            HpkeSuite suite = new HpkeSuite(
                HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256,
                HpkeSuite.Kdf.HKDF_SHA512,
                HpkeSuite.Aead.ChaCha20Poly1305);

            Assert.Equal(HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256, suite.KemAlgorithm);
            Assert.Equal(HpkeSuite.Kdf.HKDF_SHA512, suite.KdfAlgorithm);
            Assert.Equal(HpkeSuite.Aead.ChaCha20Poly1305, suite.AeadAlgorithm);
            Assert.Equal(65, suite.EncapsulationKeySizeInBytes);
            Assert.Equal(32, suite.DecapsulationKeySizeInBytes);
            Assert.Equal(65, suite.EncapsulatedKeySizeInBytes);
            Assert.Equal(16, suite.AeadTagSizeInBytes);
        }

        [Fact]
        public static void ComposedSuite_NotEqualToDifferentSuite()
        {
            HpkeSuite a = new HpkeSuite(
                HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256,
                HpkeSuite.Kdf.HKDF_SHA256,
                HpkeSuite.Aead.Aes128Gcm);

            HpkeSuite b = new HpkeSuite(
                HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256,
                HpkeSuite.Kdf.HKDF_SHA384,
                HpkeSuite.Aead.Aes128Gcm);

            Assert.NotEqual(a, b);
        }

        [Fact]
        public static void ComposedSuite_Name_ContainsComponents()
        {
            HpkeSuite suite = new HpkeSuite(
                HpkeSuite.Kem.DHKEM_P384_HKDF_SHA384,
                HpkeSuite.Kdf.HKDF_SHA512,
                HpkeSuite.Aead.Aes256Gcm);

            Assert.Contains("P-384", suite.Name);
            Assert.Contains("HKDF-SHA512", suite.Name);
            Assert.Contains("AES-256-GCM", suite.Name);
        }

        [Theory]
        [InlineData((HpkeSuite.Kem)0)]
        [InlineData((HpkeSuite.Kem)99)]
        [InlineData((HpkeSuite.Kem)(-1))]
        public static void Constructor_InvalidKem_Throws(HpkeSuite.Kem kem)
        {
            Assert.Throws<ArgumentOutOfRangeException>("kem", () =>
                new HpkeSuite(kem, HpkeSuite.Kdf.HKDF_SHA256, HpkeSuite.Aead.Aes128Gcm));
        }

        [Theory]
        [InlineData((HpkeSuite.Kdf)0)]
        [InlineData((HpkeSuite.Kdf)99)]
        [InlineData((HpkeSuite.Kdf)(-1))]
        public static void Constructor_InvalidKdf_Throws(HpkeSuite.Kdf kdf)
        {
            Assert.Throws<ArgumentOutOfRangeException>("kdf", () =>
                new HpkeSuite(HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256, kdf, HpkeSuite.Aead.Aes128Gcm));
        }

        [Theory]
        [InlineData((HpkeSuite.Aead)0)]
        [InlineData((HpkeSuite.Aead)99)]
        [InlineData((HpkeSuite.Aead)(-1))]
        public static void Constructor_InvalidAead_Throws(HpkeSuite.Aead aead)
        {
            Assert.Throws<ArgumentOutOfRangeException>("aead", () =>
                new HpkeSuite(HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256, HpkeSuite.Kdf.HKDF_SHA256, aead));
        }
    }
}
