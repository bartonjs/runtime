// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text;
using Xunit;

namespace System.Security.Cryptography.Tests
{
    public class HpkeTests_IsSupported
    {
        [Fact]
        public static void IsSupported_AgreesWithPlatform()
        {
            Assert.Equal(!PlatformDetection.IsBrowser, HPKE.IsSupported);
        }
    }

    [ConditionalClass(typeof(HPKE), nameof(HPKE.IsSupported))]
    public class HpkeTests
    {
        public static TheoryData<HpkeSuite> NistSuites => new()
        {
            HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM,
            HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM,
        };

        [Fact]
        public void GenerateKey_NullSuite()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () => HPKE.GenerateKey(null));
        }

        [Fact]
        public void ImportEncapsulationKey_NullSuite_Span()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () =>
                HPKE.ImportEncapsulationKey(null, new ReadOnlySpan<byte>(new byte[65])));
        }

        [Fact]
        public void ImportEncapsulationKey_NullSuite_Array()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () =>
                HPKE.ImportEncapsulationKey(null, new byte[65]));
        }

        [Fact]
        public void ImportEncapsulationKey_NullSource()
        {
            AssertExtensions.Throws<ArgumentNullException>("source", static () =>
                HPKE.ImportEncapsulationKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, (byte[])null));
        }

        [Fact]
        public void ImportDecapsulationKey_NullSuite_Span()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () =>
                HPKE.ImportDecapsulationKey(null, new ReadOnlySpan<byte>(new byte[32])));
        }

        [Fact]
        public void ImportDecapsulationKey_NullSuite_Array()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () =>
                HPKE.ImportDecapsulationKey(null, new byte[32]));
        }

        [Fact]
        public void ImportDecapsulationKey_NullSource()
        {
            AssertExtensions.Throws<ArgumentNullException>("source", static () =>
                HPKE.ImportDecapsulationKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, (byte[])null));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void ExportEncapsulationKey_WrongSize(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                key.ExportEncapsulationKey(new byte[suite.EncapsulationKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                key.ExportEncapsulationKey(new byte[suite.EncapsulationKeySizeInBytes + 1]));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void ExportDecapsulationKey_WrongSize(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                key.ExportDecapsulationKey(new byte[suite.DecapsulationKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                key.ExportDecapsulationKey(new byte[suite.DecapsulationKeySizeInBytes + 1]));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_RoundTrip(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            byte[] plaintext = "Hello, HPKE!"u8.ToArray();
            byte[] aad = "additional data"u8.ToArray();

            (byte[] kemCiphertext, byte[] ciphertext) = key.Seal(plaintext, aad);

            Assert.Equal(suite.EncapsulatedKeySizeInBytes, kemCiphertext.Length);
            Assert.Equal(plaintext.Length + suite.AeadTagSizeInBytes, ciphertext.Length);

            byte[] decrypted = key.Open(kemCiphertext, ciphertext, aad: aad);
            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_SpanOverloads(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            ReadOnlySpan<byte> plaintext = "Span overload test"u8;
            Span<byte> kemCiphertext = new byte[suite.EncapsulatedKeySizeInBytes];
            Span<byte> ciphertext = new byte[plaintext.Length + suite.AeadTagSizeInBytes];

            key.Seal(plaintext, kemCiphertext, ciphertext);

            Span<byte> decrypted = new byte[plaintext.Length];
            key.Open((ReadOnlySpan<byte>)kemCiphertext, (ReadOnlySpan<byte>)ciphertext, decrypted);

            Assert.True(plaintext.SequenceEqual(decrypted));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_WithInfo(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            byte[] plaintext = "with info"u8.ToArray();
            byte[] info = "application context"u8.ToArray();

            (byte[] kemCiphertext, byte[] ciphertext) = key.Seal(plaintext, info: info);
            byte[] decrypted = key.Open(kemCiphertext, ciphertext, info: info);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_WrongInfo_Fails(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            byte[] plaintext = "wrong info test"u8.ToArray();
            byte[] info1 = "info one"u8.ToArray();
            byte[] info2 = "info two"u8.ToArray();

            (byte[] kemCiphertext, byte[] ciphertext) = key.Seal(plaintext, info: info1);

            Assert.ThrowsAny<CryptographicException>(() =>
                key.Open(kemCiphertext, ciphertext, info: info2));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_WrongKey_Fails(HpkeSuite suite)
        {
            using HPKE sender = HPKE.GenerateKey(suite);
            using HPKE wrongRecipient = HPKE.GenerateKey(suite);

            byte[] plaintext = "wrong key test"u8.ToArray();

            (byte[] kemCiphertext, byte[] ciphertext) = sender.Seal(plaintext);

            Assert.ThrowsAny<CryptographicException>(() =>
                wrongRecipient.Open(kemCiphertext, ciphertext));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_WrongAad_Fails(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            byte[] plaintext = "wrong aad test"u8.ToArray();
            byte[] aad1 = "aad one"u8.ToArray();
            byte[] aad2 = "aad two"u8.ToArray();

            (byte[] kemCiphertext, byte[] ciphertext) = key.Seal(plaintext, aad1);

            Assert.ThrowsAny<CryptographicException>(() =>
                key.Open(kemCiphertext, ciphertext, aad: aad2));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_TamperedCiphertext_Fails(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            byte[] plaintext = "tampered ciphertext test"u8.ToArray();

            (byte[] kemCiphertext, byte[] ciphertext) = key.Seal(plaintext);

            ciphertext[0] ^= 0xFF;

            Assert.ThrowsAny<CryptographicException>(() =>
                key.Open(kemCiphertext, ciphertext));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_EmptyPlaintext(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, byte[] ciphertext) = key.Seal(ReadOnlySpan<byte>.Empty);

            Assert.Equal(suite.AeadTagSizeInBytes, ciphertext.Length);

            byte[] decrypted = key.Open(kemCiphertext, ciphertext);
            Assert.Empty(decrypted);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_MultiMessage_RoundTrip(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender();
            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext))
            {
                for (int i = 0; i < 5; i++)
                {
                    byte[] plaintext = Encoding.UTF8.GetBytes($"message {i}");
                    byte[] ciphertext = senderCtx.Seal(plaintext);
                    byte[] decrypted = receiverCtx.Open(ciphertext);

                    Assert.Equal(plaintext, decrypted);
                }
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_MultiMessage_WithAad(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender();
            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext))
            {
                for (int i = 0; i < 3; i++)
                {
                    byte[] plaintext = Encoding.UTF8.GetBytes($"msg {i}");
                    byte[] aad = Encoding.UTF8.GetBytes($"aad {i}");
                    byte[] ciphertext = senderCtx.Seal(plaintext, aad: aad);
                    byte[] decrypted = receiverCtx.Open(ciphertext, aad: aad);

                    Assert.Equal(plaintext, decrypted);
                }
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_MultiMessage_SpanOverloads(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            Span<byte> kemCiphertext = new byte[suite.EncapsulatedKeySizeInBytes];
            using HpkeSenderContext senderCtx = key.SetupSender(kemCiphertext);
            using HpkeReceiverContext receiverCtx = key.SetupReceiver((ReadOnlySpan<byte>)kemCiphertext);

            ReadOnlySpan<byte> plaintext = "span context test"u8;
            Span<byte> ciphertext = new byte[plaintext.Length + suite.AeadTagSizeInBytes];
            senderCtx.Seal(plaintext, ciphertext);

            Span<byte> decrypted = new byte[plaintext.Length];
            receiverCtx.Open((ReadOnlySpan<byte>)ciphertext, decrypted);

            Assert.True(plaintext.SequenceEqual(decrypted));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_OutOfOrder_WrongSequence_Fails(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender();
            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext))
            {
                byte[] plaintext = "sequence test"u8.ToArray();
                byte[] ct0 = senderCtx.Seal(plaintext);
                byte[] ct1 = senderCtx.Seal(plaintext);

                // Trying to open ct1 first (at seq=0) should fail because it was sealed at seq=1
                Assert.ThrowsAny<CryptographicException>(() => receiverCtx.Open(ct1));

                // But using explicit sequence number 1 should succeed
                byte[] decrypted = receiverCtx.Open(1, ct1);
                Assert.Equal(plaintext, decrypted);

                // And explicit sequence number 0 should still work for ct0
                decrypted = receiverCtx.Open(0, ct0);
                Assert.Equal(plaintext, decrypted);
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_ExplicitSequenceNumber_DoesNotAffectInternalCounter(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender();
            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext))
            {
                byte[] plaintext = "counter test"u8.ToArray();
                byte[] ct0 = senderCtx.Seal(plaintext);
                byte[] ct1 = senderCtx.Seal(plaintext);
                byte[] ct2 = senderCtx.Seal(plaintext);

                // Open ct1 with explicit seq=1 first
                byte[] d1 = receiverCtx.Open(1, ct1);
                Assert.Equal(plaintext, d1);

                // Internal counter is still at 0, so sequential Open should decrypt ct0
                byte[] d0 = receiverCtx.Open(ct0);
                Assert.Equal(plaintext, d0);

                // Internal counter is now 1, so sequential Open should decrypt ct1
                byte[] d1b = receiverCtx.Open(ct1);
                Assert.Equal(plaintext, d1b);

                // Internal counter is now 2
                byte[] d2 = receiverCtx.Open(ct2);
                Assert.Equal(plaintext, d2);
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_Export_SameSecret(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender();
            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext))
            {
                byte[] exporterContext = "test exporter"u8.ToArray();
                int exportLength = 32;

                byte[] senderExport = senderCtx.Export(exporterContext, exportLength);
                byte[] receiverExport = receiverCtx.Export(exporterContext, exportLength);

                Assert.Equal(exportLength, senderExport.Length);
                Assert.Equal(senderExport, receiverExport);
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_Export_DifferentContexts_DifferentSecrets(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender();
            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext))
            {
                byte[] export1 = senderCtx.Export("context1"u8, 32);
                byte[] export2 = senderCtx.Export("context2"u8, 32);

                Assert.NotEqual(export1, export2);
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_Export_SpanOverload(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender();
            using (senderCtx)
            {
                byte[] exporterContext = "span export"u8.ToArray();
                byte[] arrayResult = senderCtx.Export(exporterContext, 48);

                byte[] spanResult = new byte[48];
                senderCtx.Export(exporterContext, spanResult);

                Assert.Equal(arrayResult, spanResult);
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void KeyExport_EncapsulationKey_RoundTrip(HpkeSuite suite)
        {
            using HPKE original = HPKE.GenerateKey(suite);

            byte[] encapsulationKey = original.ExportEncapsulationKey();
            Assert.Equal(suite.EncapsulationKeySizeInBytes, encapsulationKey.Length);

            byte[] spanDest = new byte[suite.EncapsulationKeySizeInBytes];
            original.ExportEncapsulationKey(spanDest);
            Assert.Equal(encapsulationKey, spanDest);

            using HPKE imported = HPKE.ImportEncapsulationKey(suite, encapsulationKey);
            byte[] reExported = imported.ExportEncapsulationKey();
            Assert.Equal(encapsulationKey, reExported);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void KeyExport_DecapsulationKey_RoundTrip(HpkeSuite suite)
        {
            using HPKE original = HPKE.GenerateKey(suite);

            byte[] decapsulationKey = original.ExportDecapsulationKey();
            Assert.Equal(suite.DecapsulationKeySizeInBytes, decapsulationKey.Length);

            byte[] spanDest = new byte[suite.DecapsulationKeySizeInBytes];
            original.ExportDecapsulationKey(spanDest);
            Assert.Equal(decapsulationKey, spanDest);

            using HPKE imported = HPKE.ImportDecapsulationKey(suite, decapsulationKey);
            byte[] reExported = imported.ExportDecapsulationKey();
            Assert.Equal(decapsulationKey, reExported);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void KeyExport_ImportedDecapsulationKey_CanOpen(HpkeSuite suite)
        {
            using HPKE original = HPKE.GenerateKey(suite);

            byte[] encapsulationKey = original.ExportEncapsulationKey();
            byte[] decapsulationKey = original.ExportDecapsulationKey();

            using HPKE pubOnly = HPKE.ImportEncapsulationKey(suite, encapsulationKey);
            using HPKE privKey = HPKE.ImportDecapsulationKey(suite, decapsulationKey);

            byte[] plaintext = "key roundtrip seal/open"u8.ToArray();
            (byte[] kemCiphertext, byte[] ciphertext) = pubOnly.Seal(plaintext);

            byte[] decrypted = privKey.Open(kemCiphertext, ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void KeyExport_PublicKeyOnly_CannotOpen(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);
            byte[] encapsulationKey = key.ExportEncapsulationKey();

            using HPKE pubOnly = HPKE.ImportEncapsulationKey(suite, encapsulationKey);

            byte[] plaintext = "cannot open test"u8.ToArray();
            (byte[] kemCiphertext, byte[] ciphertext) = pubOnly.Seal(plaintext);

            Assert.ThrowsAny<CryptographicException>(() =>
                pubOnly.Open(kemCiphertext, ciphertext));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void KeyExport_PublicKeyOnly_CannotExportDecapsulationKey(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);
            byte[] encapsulationKey = key.ExportEncapsulationKey();

            using HPKE pubOnly = HPKE.ImportEncapsulationKey(suite, encapsulationKey);

            Assert.ThrowsAny<CryptographicException>(() =>
                pubOnly.ExportDecapsulationKey());
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Disposed_ThrowsObjectDisposedException(HpkeSuite suite)
        {
            HPKE key = HPKE.GenerateKey(suite);
            key.Dispose();

            Assert.Throws<ObjectDisposedException>(() => key.ExportEncapsulationKey());
            Assert.Throws<ObjectDisposedException>(() => key.ExportDecapsulationKey());
            Assert.Throws<ObjectDisposedException>(() => key.Seal("test"u8));
            Assert.Throws<ObjectDisposedException>(() => key.Open(new byte[suite.EncapsulatedKeySizeInBytes], new byte[suite.AeadTagSizeInBytes]));
            Assert.Throws<ObjectDisposedException>(() => key.SetupSender());
            Assert.Throws<ObjectDisposedException>(() => key.SetupReceiver(new byte[suite.EncapsulatedKeySizeInBytes]));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SenderContext_Disposed_ThrowsObjectDisposedException(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);
            (_, HpkeSenderContext senderCtx) = key.SetupSender();
            senderCtx.Dispose();

            Assert.Throws<ObjectDisposedException>(() => senderCtx.Seal("test"u8));
            Assert.Throws<ObjectDisposedException>(() => senderCtx.Export("ctx"u8, 32));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void ReceiverContext_Disposed_ThrowsObjectDisposedException(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);
            (byte[] kemCiphertext, _) = key.SetupSender();

            HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext);
            receiverCtx.Dispose();

            Assert.Throws<ObjectDisposedException>(() => receiverCtx.Open(new byte[suite.AeadTagSizeInBytes]));
            Assert.Throws<ObjectDisposedException>(() => receiverCtx.Open(0, new byte[suite.AeadTagSizeInBytes]));
            Assert.Throws<ObjectDisposedException>(() => receiverCtx.Export("ctx"u8, 32));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Seal_WrongCiphertextSize_Throws(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            byte[] plaintext = "test"u8.ToArray();
            byte[] kemCt = new byte[suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertextTooSmall = new byte[plaintext.Length + suite.AeadTagSizeInBytes - 1];

            Assert.ThrowsAny<ArgumentException>(() =>
                key.Seal((ReadOnlySpan<byte>)plaintext, (Span<byte>)kemCt, (Span<byte>)ciphertextTooSmall));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Seal_WrongKemCiphertextSize_Throws(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            byte[] plaintext = "test"u8.ToArray();
            byte[] kemCiphertextWrong = new byte[suite.EncapsulatedKeySizeInBytes + 1];
            byte[] ciphertext = new byte[plaintext.Length + suite.AeadTagSizeInBytes];

            Assert.ThrowsAny<ArgumentException>(() =>
                key.Seal((ReadOnlySpan<byte>)plaintext, (Span<byte>)kemCiphertextWrong, (Span<byte>)ciphertext));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Open_CiphertextTooSmall_Throws(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            byte[] kemCiphertext = new byte[suite.EncapsulatedKeySizeInBytes];
            byte[] tooSmall = new byte[suite.AeadTagSizeInBytes - 1];

            Assert.ThrowsAny<ArgumentException>(() =>
                key.Open(kemCiphertext, tooSmall));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void ExplicitSequenceNumber_Negative_Throws(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);
            (byte[] kemCiphertext, _) = key.SetupSender();
            using HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext);

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                receiverCtx.Open(-1, new byte[suite.AeadTagSizeInBytes]));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Export_ZeroLength_Throws(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);
            (_, HpkeSenderContext senderCtx) = key.SetupSender();
            using (senderCtx)
            {
                Assert.Throws<ArgumentOutOfRangeException>(() =>
                    senderCtx.Export("ctx"u8, 0));

                Assert.ThrowsAny<ArgumentException>(() =>
                    senderCtx.Export("ctx"u8, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_WithInfo(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);
            byte[] info = "context with info"u8.ToArray();

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender(info: (ReadOnlySpan<byte>)info);
            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext, info))
            {
                byte[] plaintext = "hello with info context"u8.ToArray();
                byte[] ciphertext = senderCtx.Seal(plaintext);
                byte[] decrypted = receiverCtx.Open(ciphertext);

                Assert.Equal(plaintext, decrypted);
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_MismatchedInfo_Fails(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender("info A"u8);
            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext, "info B"u8))
            {
                byte[] plaintext = "mismatched info"u8.ToArray();
                byte[] ciphertext = senderCtx.Seal(plaintext);

                Assert.ThrowsAny<CryptographicException>(() =>
                    receiverCtx.Open(ciphertext));
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void DoubleDispose_DoesNotThrow(HpkeSuite suite)
        {
            HPKE key = HPKE.GenerateKey(suite);
            key.Dispose();
            key.Dispose();
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_DoubleDispose_DoesNotThrow(HpkeSuite suite)
        {
            using HPKE key = HPKE.GenerateKey(suite);
            (_, HpkeSenderContext senderCtx) = key.SetupSender();
            senderCtx.Dispose();
            senderCtx.Dispose();
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void PskMode_SetupSenderReceiver_RoundTrip(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSenderPsk(psk, pskId);

            using (senderCtx)
            {
                using HpkeReceiverContext receiverCtx = key.SetupReceiverPsk(kemCiphertext, psk, pskId);

                byte[] plaintext = "Hello, PSK HPKE!"u8.ToArray();
                byte[] aad = "associated-data"u8.ToArray();

                byte[] ciphertext = senderCtx.Seal(plaintext, aad);
                byte[] decrypted = receiverCtx.Open(ciphertext, aad);

                Assert.Equal(plaintext, decrypted);
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void PskMode_WrongPsk_FailsToDecrypt(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            byte[] wrongPsk = new byte[32];
            RandomNumberGenerator.Fill(wrongPsk);

            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSenderPsk(psk, pskId);

            using (senderCtx)
            {
                byte[] plaintext = "Hello, PSK HPKE!"u8.ToArray();
                byte[] aad = "associated-data"u8.ToArray();

                byte[] ciphertext = senderCtx.Seal(plaintext, aad);

                using HpkeReceiverContext receiverCtx = key.SetupReceiverPsk(kemCiphertext, wrongPsk, pskId);
                Assert.ThrowsAny<CryptographicException>(() => receiverCtx.Open(ciphertext, aad));
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void PskMode_WrongPskId_FailsToDecrypt(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            byte[] wrongPskId = "wrong-psk-id"u8.ToArray();

            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSenderPsk(psk, pskId);

            using (senderCtx)
            {
                byte[] plaintext = "Hello, PSK HPKE!"u8.ToArray();
                byte[] aad = "associated-data"u8.ToArray();

                byte[] ciphertext = senderCtx.Seal(plaintext, aad);

                using HpkeReceiverContext receiverCtx = key.SetupReceiverPsk(kemCiphertext, psk, wrongPskId);
                Assert.ThrowsAny<CryptographicException>(() => receiverCtx.Open(ciphertext, aad));
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void PskMode_MultipleMessages(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "multi-msg-psk"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSenderPsk(psk, pskId);

            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiverPsk(kemCiphertext, psk, pskId))
            {
                for (int i = 0; i < 5; i++)
                {
                    byte[] plaintext = System.Text.Encoding.UTF8.GetBytes($"Message {i}");
                    byte[] aad = System.Text.Encoding.UTF8.GetBytes($"Count-{i}");

                    byte[] ciphertext = senderCtx.Seal(plaintext, aad);
                    byte[] decrypted = receiverCtx.Open(ciphertext, aad);

                    Assert.Equal(plaintext, decrypted);
                }
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void PskMode_WithInfo(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "info-test-psk"u8.ToArray();
            byte[] info = "application-context"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using HPKE key = HPKE.GenerateKey(suite);

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSenderPsk(psk, pskId, info);

            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = key.SetupReceiverPsk(
                new ReadOnlySpan<byte>(kemCiphertext), psk, pskId, info))
            {
                byte[] plaintext = "With info!"u8.ToArray();
                byte[] ciphertext = senderCtx.Seal(plaintext);
                byte[] decrypted = receiverCtx.Open(ciphertext);

                Assert.Equal(plaintext, decrypted);
            }
        }

        [Fact]
        public void PskMode_EmptyPsk_Throws()
        {
            using HPKE key = HPKE.GenerateKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            byte[] kemCt = new byte[key.Suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("psk", () =>
                key.SetupSenderPsk(kemCt.AsSpan(), ReadOnlySpan<byte>.Empty, new byte[] { 1 }));

            AssertExtensions.Throws<ArgumentException>("psk", () =>
                key.SetupReceiverPsk(new ReadOnlySpan<byte>(kemCt), ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public void PskMode_EmptyPskId_Throws()
        {
            using HPKE key = HPKE.GenerateKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            byte[] kemCt = new byte[key.Suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                key.SetupSenderPsk(kemCt.AsSpan(), new byte[] { 1 }, ReadOnlySpan<byte>.Empty));

            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                key.SetupReceiverPsk(new ReadOnlySpan<byte>(kemCt), new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthMode_SetupSenderReceiver_RoundTrip(HpkeSuite suite)
        {
            using HPKE recipientKey = HPKE.GenerateKey(suite);
            using HPKE senderKey = HPKE.GenerateKey(suite);
            using HPKE senderPublicKey = HPKE.ImportEncapsulationKey(suite, senderKey.ExportEncapsulationKey());

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = recipientKey.SetupSenderAuth(senderKey, default(ReadOnlySpan<byte>));

            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = recipientKey.SetupReceiverAuth(kemCiphertext, senderPublicKey))
            {
                byte[] plaintext = "Hello, Auth HPKE!"u8.ToArray();
                byte[] aad = "associated-data"u8.ToArray();

                byte[] ciphertext = senderCtx.Seal(plaintext, aad);
                byte[] decrypted = receiverCtx.Open(ciphertext, aad);

                Assert.Equal(plaintext, decrypted);
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthMode_WrongSenderKey_FailsToDecrypt(HpkeSuite suite)
        {
            using HPKE recipientKey = HPKE.GenerateKey(suite);
            using HPKE senderKey = HPKE.GenerateKey(suite);
            using HPKE wrongSenderKey = HPKE.GenerateKey(suite);
            using HPKE wrongSenderPublicKey = HPKE.ImportEncapsulationKey(suite, wrongSenderKey.ExportEncapsulationKey());

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = recipientKey.SetupSenderAuth(senderKey, default(ReadOnlySpan<byte>));

            using (senderCtx)
            {
                byte[] plaintext = "Hello, Auth HPKE!"u8.ToArray();
                byte[] aad = "associated-data"u8.ToArray();
                byte[] ciphertext = senderCtx.Seal(plaintext, aad);

                using HpkeReceiverContext receiverCtx = recipientKey.SetupReceiverAuth(kemCiphertext, wrongSenderPublicKey);
                Assert.ThrowsAny<CryptographicException>(() => receiverCtx.Open(ciphertext, aad));
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthMode_DisposedSenderKey_Throws(HpkeSuite suite)
        {
            using HPKE recipientKey = HPKE.GenerateKey(suite);
            HPKE senderKey = HPKE.GenerateKey(suite);
            senderKey.Dispose();

            Assert.Throws<ObjectDisposedException>(() => recipientKey.SetupSenderAuth(senderKey, default(ReadOnlySpan<byte>)));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthMode_PublicOnlySenderKey_Throws(HpkeSuite suite)
        {
            using HPKE recipientKey = HPKE.GenerateKey(suite);
            using HPKE senderKey = HPKE.GenerateKey(suite);
            using HPKE senderPublicKey = HPKE.ImportEncapsulationKey(suite, senderKey.ExportEncapsulationKey());

            Assert.ThrowsAny<CryptographicException>(() =>
                recipientKey.SetupSenderAuth(senderPublicKey, default(ReadOnlySpan<byte>)));
        }

        [Fact]
        public void AuthMode_MismatchedSuite_Throws()
        {
            using HPKE recipientKey = HPKE.GenerateKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            using HPKE senderKey = HPKE.GenerateKey(HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM);

            AssertExtensions.Throws<ArgumentException>("senderKey", () =>
                recipientKey.SetupSenderAuth(senderKey, default(ReadOnlySpan<byte>)));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthPskMode_SetupSenderReceiver_RoundTrip(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-auth-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using HPKE recipientKey = HPKE.GenerateKey(suite);
            using HPKE senderKey = HPKE.GenerateKey(suite);
            using HPKE senderPublicKey = HPKE.ImportEncapsulationKey(suite, senderKey.ExportEncapsulationKey());

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = recipientKey.SetupSenderAuthPsk(senderKey, psk, pskId);

            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = recipientKey.SetupReceiverAuthPsk(kemCiphertext, senderPublicKey, psk, pskId))
            {
                byte[] plaintext = "Hello, AuthPSK HPKE!"u8.ToArray();
                byte[] aad = "associated-data"u8.ToArray();

                byte[] ciphertext = senderCtx.Seal(plaintext, aad);
                byte[] decrypted = receiverCtx.Open(ciphertext, aad);

                Assert.Equal(plaintext, decrypted);
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthPskMode_WrongSenderKey_FailsToDecrypt(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-auth-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using HPKE recipientKey = HPKE.GenerateKey(suite);
            using HPKE senderKey = HPKE.GenerateKey(suite);
            using HPKE wrongSenderKey = HPKE.GenerateKey(suite);
            using HPKE wrongSenderPublicKey = HPKE.ImportEncapsulationKey(suite, wrongSenderKey.ExportEncapsulationKey());

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = recipientKey.SetupSenderAuthPsk(senderKey, psk, pskId);

            using (senderCtx)
            {
                byte[] plaintext = "Hello, AuthPSK HPKE!"u8.ToArray();
                byte[] aad = "associated-data"u8.ToArray();
                byte[] ciphertext = senderCtx.Seal(plaintext, aad);

                using HpkeReceiverContext receiverCtx = recipientKey.SetupReceiverAuthPsk(kemCiphertext, wrongSenderPublicKey, psk, pskId);
                Assert.ThrowsAny<CryptographicException>(() => receiverCtx.Open(ciphertext, aad));
            }
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthPskMode_DisposedSenderKey_Throws(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-auth-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using HPKE recipientKey = HPKE.GenerateKey(suite);
            HPKE senderKey = HPKE.GenerateKey(suite);
            senderKey.Dispose();

            Assert.Throws<ObjectDisposedException>(() => recipientKey.SetupSenderAuthPsk(senderKey, psk, pskId));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthPskMode_PublicOnlySenderKey_Throws(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-auth-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using HPKE recipientKey = HPKE.GenerateKey(suite);
            using HPKE senderKey = HPKE.GenerateKey(suite);
            using HPKE senderPublicKey = HPKE.ImportEncapsulationKey(suite, senderKey.ExportEncapsulationKey());

            Assert.ThrowsAny<CryptographicException>(() =>
                recipientKey.SetupSenderAuthPsk(senderPublicKey, psk, pskId));
        }

        [Fact]
        public void AuthPskMode_MismatchedSuite_Throws()
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-auth-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using HPKE recipientKey = HPKE.GenerateKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            using HPKE senderKey = HPKE.GenerateKey(HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM);

            AssertExtensions.Throws<ArgumentException>("senderKey", () =>
                recipientKey.SetupSenderAuthPsk(senderKey, psk, pskId));
        }

        [Fact]
        public void Rfc9180_A33_AuthMode_P256_Sha256_Aes128Gcm()
        {
            byte[] skRm = Convert.FromHexString("d929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e");
            byte[] pkSm = Convert.FromHexString(
                "04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef" +
                "8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73");
            byte[] enc = Convert.FromHexString(
                "042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b" +
                "79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454");
            byte[] info = Convert.FromHexString("4f6465206f6e2061204772656369616e2055726e");
            byte[] aad = Convert.FromHexString("436f756e742d30");
            byte[] plaintext = Convert.FromHexString("4265617574792069732074727574682c20747275746820626561757479");
            byte[] ciphertext = Convert.FromHexString(
                "82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2" +
                "bdb8f265db4a099ed3289ffe19");

            using HPKE recipientKey = HPKE.ImportDecapsulationKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, skRm);
            using HPKE senderPublicKey = HPKE.ImportEncapsulationKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, pkSm);
            using HpkeReceiverContext receiverCtx = recipientKey.SetupReceiverAuth(enc, senderPublicKey, info);

            Assert.Equal(plaintext, receiverCtx.Open(ciphertext, aad));
        }

        [Fact]
        public void Rfc9180_A34_AuthPskMode_P256_Sha256_Aes128Gcm()
        {
            byte[] skRm = Convert.FromHexString("bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394");
            byte[] pkSm = Convert.FromHexString(
                "049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d04800" +
                "69133d6488bf73863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af9e");
            byte[] enc = Convert.FromHexString(
                "046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b13135" +
                "7ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a84511401");
            byte[] info = Convert.FromHexString("4f6465206f6e2061204772656369616e2055726e");
            byte[] psk = Convert.FromHexString("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
            byte[] pskId = Convert.FromHexString("456e6e796e20447572696e206172616e204d6f726961");
            byte[] aad = Convert.FromHexString("436f756e742d30");
            byte[] plaintext = Convert.FromHexString("4265617574792069732074727574682c20747275746820626561757479");
            byte[] ciphertext = Convert.FromHexString(
                "b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d44365407d" +
                "b8e655c72e4fa46f4ff81b9246");

            using HPKE recipientKey = HPKE.ImportDecapsulationKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, skRm);
            using HPKE senderPublicKey = HPKE.ImportEncapsulationKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, pkSm);
            using HpkeReceiverContext receiverCtx = recipientKey.SetupReceiverAuthPsk(enc, senderPublicKey, psk, pskId, info);

            Assert.Equal(plaintext, receiverCtx.Open(ciphertext, aad));
        }

        [Fact]
        public void Rfc9180_A32_PskMode_P256_Sha256_Aes128Gcm()
        {
            // RFC 9180 Appendix A.3.2 test vector
            byte[] skRm = Convert.FromHexString("438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661");
            byte[] enc = Convert.FromHexString(
                "04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89" +
                "e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f");
            byte[] info = Convert.FromHexString("4f6465206f6e2061204772656369616e2055726e");
            byte[] psk = Convert.FromHexString("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
            byte[] pskId = Convert.FromHexString("456e6e796e20447572696e206172616e204d6f726961");

            // Expected key schedule outputs
            byte[] expectedKey = Convert.FromHexString("55d9eb9d26911d4c514a990fa8d57048");
            byte[] expectedBaseNonce = Convert.FromHexString("b595dc6b2d7e2ed23af529b1");
            byte[] expectedExporterSecret = Convert.FromHexString(
                "895a723a1eab809804973a53c0ee18ece29b25a7555a4808277ad2651d66d705");

            // Encryption test vectors (seq=0)
            byte[] pt0 = Convert.FromHexString("4265617574792069732074727574682c20747275746820626561757479");
            byte[] aad0 = Convert.FromHexString("436f756e742d30");
            byte[] ct0 = Convert.FromHexString(
                "90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1a" +
                "c2603193b60a49c2126b75d0eb");

            // Import the recipient private key for P-256
            using HPKE key = HPKE.ImportDecapsulationKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, skRm);

            using HpkeReceiverContext receiverCtx = key.SetupReceiverPsk(
                new ReadOnlySpan<byte>(enc), psk, pskId, info);

            // Decrypt sequence 0
            byte[] decrypted = receiverCtx.Open(ct0, aad0);
            Assert.Equal(pt0, decrypted);

            // Decrypt sequence 1
            byte[] pt1 = Convert.FromHexString("4265617574792069732074727574682c20747275746820626561757479");
            byte[] aad1 = Convert.FromHexString("436f756e742d31");
            byte[] ct1 = Convert.FromHexString(
                "9e223384a3620f4a75b5a52f546b7262d8826dea18db5a365feb8b997180b22d" +
                "72dc1287f7089a1073a7102c27");
            byte[] decrypted1 = receiverCtx.Open(ct1, aad1);
            Assert.Equal(pt1, decrypted1);

            // Decrypt sequence 2
            byte[] aad2 = Convert.FromHexString("436f756e742d32");
            byte[] ct2 = Convert.FromHexString(
                "adf9f6000773035023be7d415e13f84c1cb32a24339a32eb81df02be9ddc6abc" +
                "880dd81cceb7c1d0c7781465b2");
            byte[] decrypted2 = receiverCtx.Open(ct2, aad2);
            Assert.Equal(pt1, decrypted2);
        }
    }
}
