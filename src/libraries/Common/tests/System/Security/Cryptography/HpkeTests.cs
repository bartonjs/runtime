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
            Assert.Equal(!PlatformDetection.IsBrowser, Hpke.IsSupported);
        }
    }

    [ConditionalClass(typeof(Hpke), nameof(Hpke.IsSupported))]
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
            AssertExtensions.Throws<ArgumentNullException>("suite", static () => Hpke.GenerateKey(null));
        }

        [Fact]
        public void ImportEncapsulationKey_NullSuite_Span()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () =>
                Hpke.ImportEncapsulationKey(null, new ReadOnlySpan<byte>(new byte[65])));
        }

        [Fact]
        public void ImportEncapsulationKey_NullSuite_Array()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () =>
                Hpke.ImportEncapsulationKey(null, new byte[65]));
        }

        [Fact]
        public void ImportEncapsulationKey_NullSource()
        {
            AssertExtensions.Throws<ArgumentNullException>("source", static () =>
                Hpke.ImportEncapsulationKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, (byte[])null));
        }

        [Fact]
        public void ImportDecapsulationKey_NullSuite_Span()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () =>
                Hpke.ImportDecapsulationKey(null, new ReadOnlySpan<byte>(new byte[32])));
        }

        [Fact]
        public void ImportDecapsulationKey_NullSuite_Array()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () =>
                Hpke.ImportDecapsulationKey(null, new byte[32]));
        }

        [Fact]
        public void ImportDecapsulationKey_NullSource()
        {
            AssertExtensions.Throws<ArgumentNullException>("source", static () =>
                Hpke.ImportDecapsulationKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM, (byte[])null));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void ExportEncapsulationKey_WrongSize(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                key.ExportEncapsulationKey(new byte[suite.EncapsulationKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                key.ExportEncapsulationKey(new byte[suite.EncapsulationKeySizeInBytes + 1]));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void ExportDecapsulationKey_WrongSize(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                key.ExportDecapsulationKey(new byte[suite.DecapsulationKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                key.ExportDecapsulationKey(new byte[suite.DecapsulationKeySizeInBytes + 1]));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_RoundTrip(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

            byte[] plaintext = "Hello, Hpke!"u8.ToArray();
            byte[] aad = "additional data"u8.ToArray();

            key.Seal(plaintext, out byte[] kemCiphertext, out byte[] ciphertext, aad);

            Assert.Equal(suite.EncapsulatedKeySizeInBytes, kemCiphertext.Length);
            Assert.Equal(plaintext.Length + suite.AeadTagSizeInBytes, ciphertext.Length);

            byte[] decrypted = key.Open(kemCiphertext, ciphertext, aad: aad);
            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_SpanOverloads(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

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
            using Hpke key = Hpke.GenerateKey(suite);

            byte[] plaintext = "with info"u8.ToArray();
            byte[] info = "application context"u8.ToArray();

            key.Seal(plaintext, out byte[] kemCiphertext, out byte[] ciphertext, info: info);
            byte[] decrypted = key.Open(kemCiphertext, ciphertext, info: info);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_WrongInfo_Fails(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

            byte[] plaintext = "wrong info test"u8.ToArray();
            byte[] info1 = "info one"u8.ToArray();
            byte[] info2 = "info two"u8.ToArray();

            key.Seal(plaintext, out byte[] kemCiphertext, out byte[] ciphertext, info: info1);

            Assert.ThrowsAny<CryptographicException>(() =>
                key.Open(kemCiphertext, ciphertext, info: info2));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_WrongKey_Fails(HpkeSuite suite)
        {
            using Hpke sender = Hpke.GenerateKey(suite);
            using Hpke wrongRecipient = Hpke.GenerateKey(suite);

            byte[] plaintext = "wrong key test"u8.ToArray();

            sender.Seal(plaintext, out byte[] kemCiphertext, out byte[] ciphertext);

            Assert.ThrowsAny<CryptographicException>(() =>
                wrongRecipient.Open(kemCiphertext, ciphertext));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_WrongAad_Fails(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

            byte[] plaintext = "wrong aad test"u8.ToArray();
            byte[] aad1 = "aad one"u8.ToArray();
            byte[] aad2 = "aad two"u8.ToArray();

            key.Seal(plaintext, out byte[] kemCiphertext, out byte[] ciphertext, aad1);

            Assert.ThrowsAny<CryptographicException>(() =>
                key.Open(kemCiphertext, ciphertext, aad: aad2));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_TamperedCiphertext_Fails(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

            byte[] plaintext = "tampered ciphertext test"u8.ToArray();

            key.Seal(plaintext, out byte[] kemCiphertext, out byte[] ciphertext);

            ciphertext[0] ^= 0xFF;

            Assert.ThrowsAny<CryptographicException>(() =>
                key.Open(kemCiphertext, ciphertext));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SingleShotSealOpen_EmptyPlaintext(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

            key.Seal(ReadOnlySpan<byte>.Empty, out byte[] kemCiphertext, out byte[] ciphertext);

            Assert.Equal(suite.AeadTagSizeInBytes, ciphertext.Length);

            byte[] decrypted = key.Open(kemCiphertext, ciphertext);
            Assert.Empty(decrypted);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_MultiMessage_RoundTrip(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSender(out byte[] kemCiphertext);
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
            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSender(out byte[] kemCiphertext);
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
            using Hpke key = Hpke.GenerateKey(suite);

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
        public void Context_Export_SameSecret(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSender(out byte[] kemCiphertext);
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
            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSender(out byte[] kemCiphertext);
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
            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSender(out byte[] kemCiphertext);
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
            using Hpke original = Hpke.GenerateKey(suite);

            byte[] encapsulationKey = original.ExportEncapsulationKey();
            Assert.Equal(suite.EncapsulationKeySizeInBytes, encapsulationKey.Length);

            byte[] spanDest = new byte[suite.EncapsulationKeySizeInBytes];
            original.ExportEncapsulationKey(spanDest);
            Assert.Equal(encapsulationKey, spanDest);

            using Hpke imported = Hpke.ImportEncapsulationKey(suite, encapsulationKey);
            byte[] reExported = imported.ExportEncapsulationKey();
            Assert.Equal(encapsulationKey, reExported);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void KeyExport_DecapsulationKey_RoundTrip(HpkeSuite suite)
        {
            using Hpke original = Hpke.GenerateKey(suite);

            byte[] decapsulationKey = original.ExportDecapsulationKey();
            Assert.Equal(suite.DecapsulationKeySizeInBytes, decapsulationKey.Length);

            byte[] spanDest = new byte[suite.DecapsulationKeySizeInBytes];
            original.ExportDecapsulationKey(spanDest);
            Assert.Equal(decapsulationKey, spanDest);

            using Hpke imported = Hpke.ImportDecapsulationKey(suite, decapsulationKey);
            byte[] reExported = imported.ExportDecapsulationKey();
            Assert.Equal(decapsulationKey, reExported);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void KeyExport_ImportedDecapsulationKey_CanOpen(HpkeSuite suite)
        {
            using Hpke original = Hpke.GenerateKey(suite);

            byte[] encapsulationKey = original.ExportEncapsulationKey();
            byte[] decapsulationKey = original.ExportDecapsulationKey();

            using Hpke pubOnly = Hpke.ImportEncapsulationKey(suite, encapsulationKey);
            using Hpke privKey = Hpke.ImportDecapsulationKey(suite, decapsulationKey);

            byte[] plaintext = "key roundtrip seal/open"u8.ToArray();
            pubOnly.Seal(plaintext, out byte[] kemCiphertext, out byte[] ciphertext);

            byte[] decrypted = privKey.Open(kemCiphertext, ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void KeyExport_PublicKeyOnly_CannotOpen(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);
            byte[] encapsulationKey = key.ExportEncapsulationKey();

            using Hpke pubOnly = Hpke.ImportEncapsulationKey(suite, encapsulationKey);

            byte[] plaintext = "cannot open test"u8.ToArray();
            pubOnly.Seal(plaintext, out byte[] kemCiphertext, out byte[] ciphertext);

            Assert.ThrowsAny<CryptographicException>(() =>
                pubOnly.Open(kemCiphertext, ciphertext));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void KeyExport_PublicKeyOnly_CannotExportDecapsulationKey(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);
            byte[] encapsulationKey = key.ExportEncapsulationKey();

            using Hpke pubOnly = Hpke.ImportEncapsulationKey(suite, encapsulationKey);

            Assert.ThrowsAny<CryptographicException>(() =>
                pubOnly.ExportDecapsulationKey());
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Disposed_ThrowsObjectDisposedException(HpkeSuite suite)
        {
            Hpke key = Hpke.GenerateKey(suite);
            key.Dispose();

            Assert.Throws<ObjectDisposedException>(() => key.ExportEncapsulationKey());
            Assert.Throws<ObjectDisposedException>(() => key.ExportDecapsulationKey());
            Assert.Throws<ObjectDisposedException>(() => key.Seal("test"u8, out byte[] _, out byte[] _));
            Assert.Throws<ObjectDisposedException>(() => key.Open(new byte[suite.EncapsulatedKeySizeInBytes], new byte[suite.AeadTagSizeInBytes]));
            Assert.Throws<ObjectDisposedException>(() => key.SetupSender(out byte[] _));
            Assert.Throws<ObjectDisposedException>(() => key.SetupReceiver(new byte[suite.EncapsulatedKeySizeInBytes]));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void SenderContext_Disposed_ThrowsObjectDisposedException(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);
            HpkeSenderContext senderCtx = key.SetupSender(out _);
            senderCtx.Dispose();

            Assert.Throws<ObjectDisposedException>(() => senderCtx.Seal("test"u8));
            Assert.Throws<ObjectDisposedException>(() => senderCtx.Export("ctx"u8, 32));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void ReceiverContext_Disposed_ThrowsObjectDisposedException(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);
            key.SetupSender(out byte[] kemCiphertext);

            HpkeReceiverContext receiverCtx = key.SetupReceiver(kemCiphertext);
            receiverCtx.Dispose();

            Assert.Throws<ObjectDisposedException>(() => receiverCtx.Open(new byte[suite.AeadTagSizeInBytes]));
            Assert.Throws<ObjectDisposedException>(() => receiverCtx.Export("ctx"u8, 32));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Seal_WrongCiphertextSize_Throws(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);

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
            using Hpke key = Hpke.GenerateKey(suite);

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
            using Hpke key = Hpke.GenerateKey(suite);

            byte[] kemCiphertext = new byte[suite.EncapsulatedKeySizeInBytes];
            byte[] tooSmall = new byte[suite.AeadTagSizeInBytes - 1];

            Assert.ThrowsAny<ArgumentException>(() =>
                key.Open(kemCiphertext, tooSmall));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Export_ZeroLength_Throws(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);
            HpkeSenderContext senderCtx = key.SetupSender(out _);

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
            using Hpke key = Hpke.GenerateKey(suite);
            byte[] info = "context with info"u8.ToArray();

            HpkeSenderContext senderCtx = key.SetupSender(out byte[] kemCiphertext, info: (ReadOnlySpan<byte>)info);
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
            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSender(out byte[] kemCiphertext, "info A"u8);
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
            Hpke key = Hpke.GenerateKey(suite);
            key.Dispose();
            key.Dispose();
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void Context_DoubleDispose_DoesNotThrow(HpkeSuite suite)
        {
            using Hpke key = Hpke.GenerateKey(suite);
            HpkeSenderContext senderCtx = key.SetupSender(out _);
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

            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSenderPsk(psk, pskId, out byte[] kemCiphertext);

            using (senderCtx)
            {
                using HpkeReceiverContext receiverCtx = key.SetupReceiverPsk(kemCiphertext, psk, pskId);

                byte[] plaintext = "Hello, PSK Hpke!"u8.ToArray();
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

            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSenderPsk(psk, pskId, out byte[] kemCiphertext);

            using (senderCtx)
            {
                byte[] plaintext = "Hello, PSK Hpke!"u8.ToArray();
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

            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSenderPsk(psk, pskId, out byte[] kemCiphertext);

            using (senderCtx)
            {
                byte[] plaintext = "Hello, PSK Hpke!"u8.ToArray();
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

            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSenderPsk(psk, pskId, out byte[] kemCiphertext);

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

            using Hpke key = Hpke.GenerateKey(suite);

            HpkeSenderContext senderCtx = key.SetupSenderPsk(psk, pskId, out byte[] kemCiphertext, info);

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
            using Hpke key = Hpke.GenerateKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            byte[] kemCt = new byte[key.Suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("psk", () =>
                key.SetupSenderPsk(ReadOnlySpan<byte>.Empty, new byte[] { 1 }, kemCt.AsSpan()));

            AssertExtensions.Throws<ArgumentException>("psk", () =>
                key.SetupReceiverPsk(new ReadOnlySpan<byte>(kemCt), ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public void PskMode_EmptyPskId_Throws()
        {
            using Hpke key = Hpke.GenerateKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            byte[] kemCt = new byte[key.Suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                key.SetupSenderPsk(new byte[] { 1 }, ReadOnlySpan<byte>.Empty, kemCt.AsSpan()));

            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                key.SetupReceiverPsk(new ReadOnlySpan<byte>(kemCt), new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthMode_SetupSenderReceiver_RoundTrip(HpkeSuite suite)
        {
            using Hpke recipientKey = Hpke.GenerateKey(suite);
            using Hpke senderKey = Hpke.GenerateKey(suite);
            using Hpke senderPublicKey = Hpke.ImportEncapsulationKey(suite, senderKey.ExportEncapsulationKey());

            HpkeSenderContext senderCtx = recipientKey.SetupSenderAuth(out byte[] kemCiphertext, senderKey, default(ReadOnlySpan<byte>));

            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = recipientKey.SetupReceiverAuth(kemCiphertext, senderPublicKey))
            {
                byte[] plaintext = "Hello, Auth Hpke!"u8.ToArray();
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
            using Hpke recipientKey = Hpke.GenerateKey(suite);
            using Hpke senderKey = Hpke.GenerateKey(suite);
            using Hpke wrongSenderKey = Hpke.GenerateKey(suite);
            using Hpke wrongSenderPublicKey = Hpke.ImportEncapsulationKey(suite, wrongSenderKey.ExportEncapsulationKey());

            HpkeSenderContext senderCtx = recipientKey.SetupSenderAuth(out byte[] kemCiphertext, senderKey, default(ReadOnlySpan<byte>));

            using (senderCtx)
            {
                byte[] plaintext = "Hello, Auth Hpke!"u8.ToArray();
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
            using Hpke recipientKey = Hpke.GenerateKey(suite);
            Hpke senderKey = Hpke.GenerateKey(suite);
            senderKey.Dispose();

            Assert.Throws<ObjectDisposedException>(() => recipientKey.SetupSenderAuth(out _, senderKey, default(ReadOnlySpan<byte>)));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthMode_PublicOnlySenderKey_Throws(HpkeSuite suite)
        {
            using Hpke recipientKey = Hpke.GenerateKey(suite);
            using Hpke senderKey = Hpke.GenerateKey(suite);
            using Hpke senderPublicKey = Hpke.ImportEncapsulationKey(suite, senderKey.ExportEncapsulationKey());

            Assert.ThrowsAny<CryptographicException>(() =>
                recipientKey.SetupSenderAuth(out _, senderPublicKey, default(ReadOnlySpan<byte>)));
        }

        [Fact]
        public void AuthMode_MismatchedSuite_Throws()
        {
            using Hpke recipientKey = Hpke.GenerateKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            using Hpke senderKey = Hpke.GenerateKey(HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM);

            AssertExtensions.Throws<ArgumentException>("senderKey", () =>
                recipientKey.SetupSenderAuth(out _, senderKey, default(ReadOnlySpan<byte>)));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthPskMode_SetupSenderReceiver_RoundTrip(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-auth-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using Hpke recipientKey = Hpke.GenerateKey(suite);
            using Hpke senderKey = Hpke.GenerateKey(suite);
            using Hpke senderPublicKey = Hpke.ImportEncapsulationKey(suite, senderKey.ExportEncapsulationKey());

            HpkeSenderContext senderCtx = recipientKey.SetupSenderAuthPsk(out byte[] kemCiphertext, senderKey, psk, pskId);

            using (senderCtx)
            using (HpkeReceiverContext receiverCtx = recipientKey.SetupReceiverAuthPsk(kemCiphertext, senderPublicKey, psk, pskId))
            {
                byte[] plaintext = "Hello, AuthPSK Hpke!"u8.ToArray();
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

            using Hpke recipientKey = Hpke.GenerateKey(suite);
            using Hpke senderKey = Hpke.GenerateKey(suite);
            using Hpke wrongSenderKey = Hpke.GenerateKey(suite);
            using Hpke wrongSenderPublicKey = Hpke.ImportEncapsulationKey(suite, wrongSenderKey.ExportEncapsulationKey());

            HpkeSenderContext senderCtx = recipientKey.SetupSenderAuthPsk(out byte[] kemCiphertext, senderKey, psk, pskId);

            using (senderCtx)
            {
                byte[] plaintext = "Hello, AuthPSK Hpke!"u8.ToArray();
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

            using Hpke recipientKey = Hpke.GenerateKey(suite);
            Hpke senderKey = Hpke.GenerateKey(suite);
            senderKey.Dispose();

            Assert.Throws<ObjectDisposedException>(() => recipientKey.SetupSenderAuthPsk(out _, senderKey, psk, pskId));
        }

        [Theory]
        [MemberData(nameof(NistSuites))]
        public void AuthPskMode_PublicOnlySenderKey_Throws(HpkeSuite suite)
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-auth-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using Hpke recipientKey = Hpke.GenerateKey(suite);
            using Hpke senderKey = Hpke.GenerateKey(suite);
            using Hpke senderPublicKey = Hpke.ImportEncapsulationKey(suite, senderKey.ExportEncapsulationKey());

            Assert.ThrowsAny<CryptographicException>(() =>
                recipientKey.SetupSenderAuthPsk(out _, senderPublicKey, psk, pskId));
        }

        [Fact]
        public void AuthPskMode_MismatchedSuite_Throws()
        {
            byte[] psk = new byte[32];
            byte[] pskId = "test-auth-psk-id"u8.ToArray();
            RandomNumberGenerator.Fill(psk);

            using Hpke recipientKey = Hpke.GenerateKey(HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM);
            using Hpke senderKey = Hpke.GenerateKey(HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM);

            AssertExtensions.Throws<ArgumentException>("senderKey", () =>
                recipientKey.SetupSenderAuthPsk(out _, senderKey, psk, pskId));
        }

    }
}
