// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text;
using Xunit;

namespace System.Security.Cryptography.Tests
{
    public class HpkeTests
    {
        public static TheoryData<HpkeSuite> NistSuites => new()
        {
            HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM,
            HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM,
        };

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

            byte[] decrypted = key.Open(kemCiphertext, ciphertext, aad);
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
                key.Open(kemCiphertext, ciphertext, aad2));
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
                    byte[] ciphertext = senderCtx.Seal(plaintext, aad);
                    byte[] decrypted = receiverCtx.Open(ciphertext, aad);

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

            (byte[] kemCiphertext, HpkeSenderContext senderCtx) = key.SetupSender(info);
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
    }
}
