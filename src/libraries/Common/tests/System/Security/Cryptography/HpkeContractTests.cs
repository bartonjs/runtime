// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.CompilerServices;
using Xunit;
using Xunit.Sdk;

namespace System.Security.Cryptography.Tests
{
    public static class HpkeContractTests
    {
        private static readonly HpkeSuite s_suite = HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM;
        private static readonly HpkeSuite s_otherSuite = HpkeSuite.DHKEM_P384_HKDF_SHA384_AES_256_GCM;

        [Fact]
        public static void Constructor_ThrowsForNullSuite()
        {
            AssertExtensions.Throws<ArgumentNullException>("suite", static () => new HpkeContract(null));
        }

        [Fact]
        public static void Constructor_SetsSuiteProperty()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Equal(s_suite, hpke.Suite);
        }

        [Fact]
        public static void Dispose_OnDisposing()
        {
            int count = 0;
            HpkeContract hpke = new(s_suite)
            {
                OnDispose = (bool disposing) =>
                {
                    count++;
                    AssertExtensions.TrueExpression(disposing);
                }
            };

            hpke.Dispose();
            hpke.Dispose();
            hpke.Dispose();

            Assert.Equal(1, count);
        }

        [Fact]
        public static void ExportEncapsulationKey_Written_WrongSize()
        {
            using HpkeContract hpke = new(s_suite);

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                hpke.ExportEncapsulationKey(new byte[s_suite.EncapsulationKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                hpke.ExportEncapsulationKey(new byte[s_suite.EncapsulationKeySizeInBytes + 1]));
        }

        [Fact]
        public static void ExportEncapsulationKey_Written_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.ExportEncapsulationKey(new byte[s_suite.EncapsulationKeySizeInBytes]));
        }

        [Fact]
        public static void ExportEncapsulationKey_Written_Works()
        {
            byte[] buffer = new byte[s_suite.EncapsulationKeySizeInBytes];
            using HpkeContract hpke = new(s_suite)
            {
                OnExportEncapsulationKeyCore = (Span<byte> destination) =>
                {
                    AssertExtensions.Same(buffer, destination);
                }
            };

            hpke.ExportEncapsulationKey(buffer);
        }

        [Fact]
        public static void ExportEncapsulationKey_Allocated_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() => hpke.ExportEncapsulationKey());
        }

        [Fact]
        public static void ExportEncapsulationKey_Allocated_Works()
        {
            using HpkeContract hpke = new(s_suite)
            {
                OnExportEncapsulationKeyCore = (Span<byte> destination) =>
                {
                    destination.Fill(0xAB);
                }
            };

            byte[] exported = hpke.ExportEncapsulationKey();
            Assert.Equal(s_suite.EncapsulationKeySizeInBytes, exported.Length);
            AssertExtensions.FilledWith<byte>(0xAB, exported);
        }

        [Fact]
        public static void ExportDecapsulationKey_Written_WrongSize()
        {
            using HpkeContract hpke = new(s_suite);

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                hpke.ExportDecapsulationKey(new byte[s_suite.DecapsulationKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("destination", () =>
                hpke.ExportDecapsulationKey(new byte[s_suite.DecapsulationKeySizeInBytes + 1]));
        }

        [Fact]
        public static void ExportDecapsulationKey_Written_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.ExportDecapsulationKey(new byte[s_suite.DecapsulationKeySizeInBytes]));
        }

        [Fact]
        public static void ExportDecapsulationKey_Written_Works()
        {
            byte[] buffer = new byte[s_suite.DecapsulationKeySizeInBytes];
            using HpkeContract hpke = new(s_suite)
            {
                OnExportDecapsulationKeyCore = (Span<byte> destination) =>
                {
                    AssertExtensions.Same(buffer, destination);
                }
            };

            hpke.ExportDecapsulationKey(buffer);
        }

        [Fact]
        public static void ExportDecapsulationKey_Allocated_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() => hpke.ExportDecapsulationKey());
        }

        [Fact]
        public static void ExportDecapsulationKey_Allocated_Works()
        {
            using HpkeContract hpke = new(s_suite)
            {
                OnExportDecapsulationKeyCore = (Span<byte> destination) =>
                {
                    destination.Fill(0xCD);
                }
            };

            byte[] exported = hpke.ExportDecapsulationKey();
            Assert.Equal(s_suite.DecapsulationKeySizeInBytes, exported.Length);
            AssertExtensions.FilledWith<byte>(0xCD, exported);
        }

        [Fact]
        public static void Seal_Span_WrongKemCiphertextSize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] plaintext = new byte[10];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.Seal(plaintext: plaintext, kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes - 1], ciphertext: ciphertext));

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.Seal(plaintext: plaintext, kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes + 1], ciphertext: ciphertext));
        }

        [Fact]
        public static void Seal_Span_WrongCiphertextSize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] plaintext = new byte[10];
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                hpke.Seal(plaintext: plaintext, kemCiphertext: kemCt, ciphertext: new byte[10 + s_suite.AeadTagSizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                hpke.Seal(plaintext: plaintext, kemCiphertext: kemCt, ciphertext: new byte[10 + s_suite.AeadTagSizeInBytes + 1]));
        }

        [Fact]
        public static void Seal_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.Seal(
                    plaintext: new byte[10],
                    kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes],
                    ciphertext: new byte[10 + s_suite.AeadTagSizeInBytes]));
        }

        [Fact]
        public static void Seal_Span_Works()
        {
            byte[] plaintext = new byte[10];
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            using HpkeContract hpke = new(s_suite)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> kemDest, Span<byte> ctDest, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(plaintext, pt);
                    AssertExtensions.Same(kemCt, kemDest);
                    AssertExtensions.Same(ciphertext, ctDest);
                }
            };

            hpke.Seal(plaintext: plaintext, kemCiphertext: kemCt, ciphertext: ciphertext);
        }

        [Fact]
        public static void Seal_Allocated_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() => hpke.Seal(new byte[10]));
        }

        [Fact]
        public static void Seal_Allocated_Works()
        {
            byte[] plaintext = "hello"u8.ToArray();
            using HpkeContract hpke = new(s_suite)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> kemDest, Span<byte> ctDest, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info) =>
                {
                    Assert.Equal(plaintext.Length, pt.Length);
                    Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemDest.Length);
                    Assert.Equal(plaintext.Length + s_suite.AeadTagSizeInBytes, ctDest.Length);
                    kemDest.Fill(0x11);
                    ctDest.Fill(0x22);
                }
            };

            (byte[] kemCiphertext, byte[] ciphertext) = hpke.Seal(plaintext);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemCiphertext.Length);
            Assert.Equal(plaintext.Length + s_suite.AeadTagSizeInBytes, ciphertext.Length);
            AssertExtensions.FilledWith<byte>(0x11, kemCiphertext);
            AssertExtensions.FilledWith<byte>(0x22, ciphertext);
        }

        [Fact]
        public static void Open_Span_WrongKemCiphertextSize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];
            byte[] plaintext = new byte[10];

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.Open(
                    kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes - 1],
                    ciphertext: ciphertext,
                    plaintext: plaintext));

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.Open(
                    kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes + 1],
                    ciphertext: ciphertext,
                    plaintext: plaintext));
        }

        [Fact]
        public static void Open_Span_CiphertextTooSmall()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                hpke.Open(kemCiphertext: kemCt, ciphertext: new byte[s_suite.AeadTagSizeInBytes - 1], plaintext: Array.Empty<byte>()));
        }

        [Fact]
        public static void Open_Span_WrongPlaintextSize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            AssertExtensions.Throws<ArgumentException>("plaintext", () =>
                hpke.Open(kemCiphertext: kemCt, ciphertext: ciphertext, plaintext: new byte[10 - 1]));

            AssertExtensions.Throws<ArgumentException>("plaintext", () =>
                hpke.Open(kemCiphertext: kemCt, ciphertext: ciphertext, plaintext: new byte[10 + 1]));
        }

        [Fact]
        public static void Open_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.Open(
                    kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes],
                    ciphertext: new byte[s_suite.AeadTagSizeInBytes],
                    plaintext: Array.Empty<byte>()));
        }

        [Fact]
        public static void Open_Span_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];
            byte[] plaintext = new byte[10];

            using HpkeContract hpke = new(s_suite)
            {
                OnOpenCore = (ReadOnlySpan<byte> kemDest, ReadOnlySpan<byte> ctSrc, Span<byte> ptDest, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(kemCt, kemDest);
                    AssertExtensions.Same(ciphertext, ctSrc);
                    AssertExtensions.Same(plaintext, ptDest);
                }
            };

            hpke.Open(kemCiphertext: kemCt, ciphertext: ciphertext, plaintext: plaintext);
        }

        [Fact]
        public static void Open_Allocated_WrongKemCiphertextSize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.Open(new byte[s_suite.EncapsulatedKeySizeInBytes - 1], ciphertext));

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.Open(new byte[s_suite.EncapsulatedKeySizeInBytes + 1], ciphertext));
        }

        [Fact]
        public static void Open_Allocated_CiphertextTooSmall()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                hpke.Open(kemCt, new byte[s_suite.AeadTagSizeInBytes - 1]));
        }

        [Fact]
        public static void Open_Allocated_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.Open(
                    new byte[s_suite.EncapsulatedKeySizeInBytes],
                    new byte[s_suite.AeadTagSizeInBytes]));
        }

        [Fact]
        public static void Open_Allocated_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            using HpkeContract hpke = new(s_suite)
            {
                OnOpenCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> ctSrc, Span<byte> ptDest, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    AssertExtensions.Same(ciphertext, ctSrc);
                    Assert.Equal(10, ptDest.Length);
                    ptDest.Fill(0x55);
                }
            };

            byte[] result = hpke.Open(kemCt, ciphertext);
            Assert.Equal(10, result.Length);
            AssertExtensions.FilledWith<byte>(0x55, result);
        }

        [Fact]
        public static void SetupSender_Span_WrongKemCiphertextSize()
        {
            using HpkeContract hpke = new(s_suite);

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.SetupSender(kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.SetupSender(kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes + 1]));
        }

        [Fact]
        public static void SetupSender_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSender(kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes]));
        }

        [Fact]
        public static void SetupSender_Span_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderCore = (Span<byte> kemDest, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(kemCt, kemDest);
                    return returnedCtx;
                }
            };

            HpkeSenderContext ctx = hpke.SetupSender(kemCiphertext: kemCt);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Allocated_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() => hpke.SetupSender());
        }

        [Fact]
        public static void SetupSender_Allocated_Works()
        {
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderCore = (Span<byte> kemDest, ReadOnlySpan<byte> info) =>
                {
                    Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemDest.Length);
                    kemDest.Fill(0x33);
                    return returnedCtx;
                }
            };

            (byte[] kemCiphertext, HpkeSenderContext ctx) = hpke.SetupSender();
            Assert.Same(returnedCtx, ctx);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemCiphertext.Length);
            AssertExtensions.FilledWith<byte>(0x33, kemCiphertext);
        }

        [Fact]
        public static void SetupReceiver_WrongKemCiphertextSize()
        {
            using HpkeContract hpke = new(s_suite);

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.SetupReceiver(new byte[s_suite.EncapsulatedKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("kemCiphertext", () =>
                hpke.SetupReceiver(new byte[s_suite.EncapsulatedKeySizeInBytes + 1]));
        }

        [Fact]
        public static void SetupReceiver_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiver(new byte[s_suite.EncapsulatedKeySizeInBytes]));
        }

        [Fact]
        public static void SetupReceiver_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    return returnedCtx;
                }
            };

            HpkeReceiverContext ctx = hpke.SetupReceiver(kemCt);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void Seal_ByteArray_NullPlaintext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Seal(
                    plaintext: (byte[])null,
                    kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes],
                    ciphertext: new byte[s_suite.AeadTagSizeInBytes]));
        }

        [Fact]
        public static void Seal_ByteArray_NullKemCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Seal(
                    plaintext: new byte[10],
                    kemCiphertext: (byte[])null,
                    ciphertext: new byte[10 + s_suite.AeadTagSizeInBytes]));
        }

        [Fact]
        public static void Seal_ByteArray_NullCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Seal(
                    plaintext: new byte[10],
                    kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes],
                    ciphertext: (byte[])null));
        }

        [Fact]
        public static void Seal_ByteArray_FunnelsToCore()
        {
            byte[] plaintext = new byte[10];
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];
            byte[] aad = new byte[3];
            byte[] info = new byte[4];

            using HpkeContract hpke = new(s_suite)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> kemDest, Span<byte> ctDest, ReadOnlySpan<byte> a, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(plaintext, pt);
                    AssertExtensions.Same(kemCt, kemDest);
                    AssertExtensions.Same(ciphertext, ctDest);
                    AssertExtensions.Same(aad, a);
                    AssertExtensions.Same(info, i);
                }
            };

            hpke.Seal(plaintext, kemCt, ciphertext, aad, info);
        }

        [Fact]
        public static void Seal_ByteArray_Allocated_NullPlaintext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Seal((byte[])null, aad: null, info: null));
        }

        [Fact]
        public static void Seal_ByteArray_Allocated_FunnelsToCore()
        {
            byte[] plaintext = "hello"u8.ToArray();

            using HpkeContract hpke = new(s_suite)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> kemDest, Span<byte> ctDest, ReadOnlySpan<byte> a, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(plaintext, pt);
                    Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemDest.Length);
                    Assert.Equal(plaintext.Length + s_suite.AeadTagSizeInBytes, ctDest.Length);
                    kemDest.Fill(0x11);
                    ctDest.Fill(0x22);
                }
            };

            (byte[] kemCiphertext, byte[] ciphertext) = hpke.Seal(plaintext, aad: null, info: null);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemCiphertext.Length);
            AssertExtensions.FilledWith<byte>(0x11, kemCiphertext);
            Assert.Equal(plaintext.Length + s_suite.AeadTagSizeInBytes, ciphertext.Length);
            AssertExtensions.FilledWith<byte>(0x22, ciphertext);
        }

        [Fact]
        public static void Open_ByteArray_NullKemCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Open(
                    kemCiphertext: (byte[])null,
                    ciphertext: new byte[s_suite.AeadTagSizeInBytes],
                    plaintext: Array.Empty<byte>()));
        }

        [Fact]
        public static void Open_ByteArray_NullCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Open(
                    kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes],
                    ciphertext: (byte[])null,
                    plaintext: Array.Empty<byte>()));
        }

        [Fact]
        public static void Open_ByteArray_NullPlaintext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Open(
                    kemCiphertext: new byte[s_suite.EncapsulatedKeySizeInBytes],
                    ciphertext: new byte[s_suite.AeadTagSizeInBytes],
                    plaintext: (byte[])null));
        }

        [Fact]
        public static void Open_ByteArray_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];
            byte[] plaintext = new byte[10];
            byte[] aad = new byte[3];
            byte[] info = new byte[4];

            using HpkeContract hpke = new(s_suite)
            {
                OnOpenCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> ctSrc, Span<byte> ptDest, ReadOnlySpan<byte> a, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    AssertExtensions.Same(ciphertext, ctSrc);
                    AssertExtensions.Same(plaintext, ptDest);
                    AssertExtensions.Same(aad, a);
                    AssertExtensions.Same(info, i);
                }
            };

            hpke.Open(kemCt, ciphertext, plaintext, aad, info);
        }

        [Fact]
        public static void Open_ByteArray_Allocated_NullKemCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Open((byte[])null, new byte[s_suite.AeadTagSizeInBytes], aad: null, info: null));
        }

        [Fact]
        public static void Open_ByteArray_Allocated_NullCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Open(new byte[s_suite.EncapsulatedKeySizeInBytes], (byte[])null, aad: null, info: null));
        }

        [Fact]
        public static void Open_ByteArray_Allocated_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            using HpkeContract hpke = new(s_suite)
            {
                OnOpenCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> ctSrc, Span<byte> ptDest, ReadOnlySpan<byte> a, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    AssertExtensions.Same(ciphertext, ctSrc);
                    Assert.Equal(10, ptDest.Length);
                    ptDest.Fill(0xAA);
                }
            };

            byte[] result = hpke.Open(kemCt, ciphertext, aad: null, info: null);
            Assert.Equal(10, result.Length);
            AssertExtensions.FilledWith<byte>(0xAA, result);
        }

        [Fact]
        public static void SetupSender_ByteArray_NullKemCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupSender((byte[])null, info: null));
        }

        [Fact]
        public static void SetupSender_ByteArray_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[4];
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderCore = (Span<byte> kemDest, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(kemCt, kemDest);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeSenderContext ctx = hpke.SetupSender(kemCt, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_ByteArray_NullKemCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupReceiver((byte[])null, info: null));
        }

        [Fact]
        public static void SetupReceiver_ByteArray_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[4];
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeReceiverContext ctx = hpke.SetupReceiver(kemCt, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Psk_Span_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupSenderPsk(kemCt.AsSpan(), ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupSender_Psk_Span_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupSenderPsk(kemCt.AsSpan(), new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void SetupSender_Psk_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderPsk(kemCt.AsSpan(), new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupSender_Psk_Span_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderPskCore = (Span<byte> kemDest, ReadOnlySpan<byte> info, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(kemCt, kemDest);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeSenderContext ctx = hpke.SetupSenderPsk(kemCt.AsSpan(), psk, pskId);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupSenderPsk(ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupSenderPsk(new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderPsk(new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_Works()
        {
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderPskCore = (Span<byte> kemDest, ReadOnlySpan<byte> info, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemDest.Length);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            (byte[] kemCiphertext, HpkeSenderContext ctx) = hpke.SetupSenderPsk(psk, pskId);
            Assert.Same(returnedCtx, ctx);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemCiphertext.Length);
        }

        [Fact]
        public static void SetupSender_Psk_ByteArray_NullPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupSenderPsk(kemCt, (byte[])null, new byte[] { 1 }, (byte[])null));
        }

        [Fact]
        public static void SetupSender_Psk_ByteArray_NullPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupSenderPsk(kemCt, new byte[] { 1 }, (byte[])null, (byte[])null));
        }

        [Fact]
        public static void SetupSender_Psk_ByteArray_NullKemCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupSenderPsk((byte[])null, new byte[] { 1 }, new byte[] { 2 }, (byte[])null));
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_NullPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupSenderPsk((byte[])null, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_NullPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupSenderPsk(new byte[] { 1 }, (byte[])null));
        }

        [Fact]
        public static void SetupSender_Psk_ByteArray_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderPskCore = (Span<byte> kemDest, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(kemCt, kemDest);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeSenderContext ctx = hpke.SetupSenderPsk(kemCt, psk, pskId, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_Psk_Span_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupReceiverPsk(new ReadOnlySpan<byte>(kemCt), ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupReceiver_Psk_Span_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupReceiverPsk(new ReadOnlySpan<byte>(kemCt), new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void SetupReceiver_Psk_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverPsk(new ReadOnlySpan<byte>(kemCt), new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupReceiver_Psk_Span_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverPskCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> info, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeReceiverContext ctx = hpke.SetupReceiverPsk(new ReadOnlySpan<byte>(kemCt), psk, pskId);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_Psk_ByteArray_NullPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupReceiverPsk(kemCt, (byte[])null, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupReceiver_Psk_ByteArray_NullPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupReceiverPsk(kemCt, new byte[] { 1 }, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_Psk_ByteArray_NullKemCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupReceiverPsk((byte[])null, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupReceiver_Psk_ByteArray_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverPskCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeReceiverContext ctx = hpke.SetupReceiverPsk(kemCt, psk, pskId, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Auth_Span_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupSenderAuth(kemCt.AsSpan(), null));
        }

        [Fact]
        public static void SetupSender_Auth_Span_Disposed()
        {
            using HpkeContract senderKey = new(s_suite);
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderAuth(kemCt.AsSpan(), senderKey));
        }

        [Fact]
        public static void SetupSender_Auth_Span_SenderDisposed()
        {
            using HpkeContract hpke = new(s_suite);
            HpkeContract senderKey = new(s_suite);
            senderKey.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderAuth(kemCt.AsSpan(), senderKey));
        }

        [Fact]
        public static void SetupSender_Auth_Span_SuiteMismatch_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_otherSuite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("senderKey", () =>
                hpke.SetupSenderAuth(kemCt.AsSpan(), senderKey));
        }

        [Fact]
        public static void SetupSender_Auth_Span_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[] { 1, 2, 3 };
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(kemCt, kemDest);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeSenderContext ctx = hpke.SetupSenderAuth(kemCt.AsSpan(), senderKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Auth_Allocated_Works()
        {
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i) =>
                {
                    Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemDest.Length);
                    Assert.Same(senderKey, sender);
                    return returnedCtx;
                }
            };

            (byte[] kemCiphertext, HpkeSenderContext ctx) = hpke.SetupSenderAuth(senderKey, default(ReadOnlySpan<byte>));
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemCiphertext.Length);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Auth_ByteArray_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupSenderAuth(kemCt, null, (byte[])null));
        }

        [Fact]
        public static void SetupSender_Auth_ByteArray_NullKemCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            AssertExtensions.Throws<ArgumentNullException>("kemCiphertext", () =>
                hpke.SetupSenderAuth((byte[])null, senderKey, (byte[])null));
        }

        [Fact]
        public static void SetupSender_Auth_Allocated_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupSenderAuth((Hpke)null, (byte[])null));
        }

        [Fact]
        public static void SetupSender_Auth_ByteArray_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(kemCt, kemDest);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeSenderContext ctx = hpke.SetupSenderAuth(kemCt, senderKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(kemCt), null));
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_SenderDisposed()
        {
            using HpkeContract hpke = new(s_suite);
            HpkeContract senderKey = new(s_suite);
            senderKey.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(kemCt), senderKey));
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_Disposed()
        {
            using HpkeContract senderKey = new(s_suite);
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(kemCt), senderKey));
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_SuiteMismatch_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_otherSuite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("senderKey", () =>
                hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(kemCt), senderKey));
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[] { 9 };
            using HpkeContract senderKey = new(s_suite);
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverAuthCore = (ReadOnlySpan<byte> kemSrc, Hpke sender, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeReceiverContext ctx = hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(kemCt), senderKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_Auth_ByteArray_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupReceiverAuth(kemCt, null, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_Auth_ByteArray_NullKemCiphertext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            AssertExtensions.Throws<ArgumentNullException>("kemCiphertext", () =>
                hpke.SetupReceiverAuth((byte[])null, senderKey, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_Auth_ByteArray_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverAuthCore = (ReadOnlySpan<byte> kemSrc, Hpke sender, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeReceiverContext ctx = hpke.SetupReceiverAuth(kemCt, senderKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupSenderAuthPsk(kemCt.AsSpan(), senderKey, ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupSenderAuthPsk(kemCt.AsSpan(), senderKey, new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_Disposed()
        {
            using HpkeContract senderKey = new(s_suite);
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderAuthPsk(kemCt.AsSpan(), senderKey, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_SenderDisposed()
        {
            using HpkeContract hpke = new(s_suite);
            HpkeContract senderKey = new(s_suite);
            senderKey.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderAuthPsk(kemCt.AsSpan(), senderKey, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthPskCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(kemCt, kemDest);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeSenderContext ctx = hpke.SetupSenderAuthPsk(kemCt.AsSpan(), senderKey, psk, pskId, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_AuthPsk_Allocated_Works()
        {
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthPskCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemDest.Length);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            (byte[] kemCiphertext, HpkeSenderContext ctx) = hpke.SetupSenderAuthPsk(senderKey, psk, pskId);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, kemCiphertext.Length);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_AuthPsk_ByteArray_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupSenderAuthPsk(kemCt, null, new byte[] { 1 }, new byte[] { 2 }, (byte[])null));
        }

        [Fact]
        public static void SetupSender_AuthPsk_ByteArray_NullPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("psk", () =>
                hpke.SetupSenderAuthPsk(kemCt, senderKey, null, new byte[] { 2 }, (byte[])null));
        }

        [Fact]
        public static void SetupSender_AuthPsk_ByteArray_NullPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("pskId", () =>
                hpke.SetupSenderAuthPsk(kemCt, senderKey, new byte[] { 1 }, null, (byte[])null));
        }

        [Fact]
        public static void SetupSender_AuthPsk_ByteArray_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthPskCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(kemCt, kemDest);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeSenderContext ctx = hpke.SetupSenderAuthPsk(kemCt, senderKey, psk, pskId, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(kemCt), senderKey, ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(kemCt), senderKey, new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_Disposed()
        {
            using HpkeContract senderKey = new(s_suite);
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(kemCt), senderKey, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_SenderDisposed()
        {
            using HpkeContract hpke = new(s_suite);
            HpkeContract senderKey = new(s_suite);
            senderKey.Dispose();
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(kemCt), senderKey, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_Works()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverAuthPskCore = (ReadOnlySpan<byte> kemSrc, Hpke sender, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeReceiverContext ctx = hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(kemCt), senderKey, psk, pskId, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_ByteArray_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupReceiverAuthPsk(kemCt, null, new byte[] { 1 }, new byte[] { 2 }, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_ByteArray_NullPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("psk", () =>
                hpke.SetupReceiverAuthPsk(kemCt, senderKey, null, new byte[] { 2 }, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_ByteArray_NullPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("pskId", () =>
                hpke.SetupReceiverAuthPsk(kemCt, senderKey, new byte[] { 1 }, null, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_ByteArray_FunnelsToCore()
        {
            byte[] kemCt = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverAuthPskCore = (ReadOnlySpan<byte> kemSrc, Hpke sender, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(kemCt, kemSrc);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeReceiverContext ctx = hpke.SetupReceiverAuthPsk(kemCt, senderKey, psk, pskId, info);
            Assert.Same(returnedCtx, ctx);
        }
    }

    public static class HpkeSenderContractTests
    {
        private const int TagSize = 7;

        [Fact]
        public static void Seal_Span_Disposed()
        {
            HpkeSenderContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                ctx.Seal(plaintext: new byte[5], ciphertext: new byte[5 + TagSize]));
        }

        [Fact]
        public static void Seal_Span_Works()
        {
            byte[] plaintext = new byte[5];
            byte[] ciphertext = new byte[5 + TagSize];

            using HpkeSenderContract ctx = new(TagSize)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> ct, ReadOnlySpan<byte> aad) =>
                {
                    AssertExtensions.Same(plaintext, pt);
                    AssertExtensions.Same(ciphertext, ct);
                }
            };

            ctx.Seal(plaintext: plaintext, ciphertext: ciphertext);
        }

        [Fact]
        public static void Seal_Allocated_Disposed()
        {
            HpkeSenderContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() => ctx.Seal(new byte[5]));
        }

        [Fact]
        public static void Seal_Allocated_Works()
        {
            using HpkeSenderContract ctx = new(TagSize)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> ct, ReadOnlySpan<byte> aad) =>
                {
                    Assert.Equal(5, pt.Length);
                    Assert.Equal(5 + TagSize, ct.Length);
                    ct.Fill(0x99);
                }
            };

            byte[] result = ctx.Seal(new byte[5]);
            Assert.Equal(5 + TagSize, result.Length);
            AssertExtensions.FilledWith<byte>(0x99, result);
        }

        [Fact]
        public static void Export_Span_ZeroLength_Throws()
        {
            using HpkeSenderContract ctx = new(TagSize);
            AssertExtensions.Throws<ArgumentException>("destination", () =>
                ctx.Export("ctx"u8, Span<byte>.Empty));
        }

        [Fact]
        public static void Export_Span_Disposed()
        {
            HpkeSenderContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                ctx.Export("ctx"u8, new byte[32]));
        }

        [Fact]
        public static void Export_Span_Works()
        {
            byte[] exporterContext = "my context"u8.ToArray();
            byte[] destination = new byte[32];

            using HpkeSenderContract ctx = new(TagSize)
            {
                OnExportCore = (ReadOnlySpan<byte> expCtx, Span<byte> dest) =>
                {
                    AssertExtensions.Same(exporterContext, expCtx);
                    AssertExtensions.Same(destination, dest);
                }
            };

            ctx.Export(exporterContext, destination);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(-100)]
        public static void Export_Allocated_InvalidLength_Throws(int length)
        {
            using HpkeSenderContract ctx = new(TagSize);
            Assert.Throws<ArgumentOutOfRangeException>(() => ctx.Export("ctx"u8, length));
        }

        [Fact]
        public static void Export_Allocated_Disposed()
        {
            HpkeSenderContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() => ctx.Export("ctx"u8, 32));
        }

        [Fact]
        public static void Export_Allocated_Works()
        {
            using HpkeSenderContract ctx = new(TagSize)
            {
                OnExportCore = (ReadOnlySpan<byte> expCtx, Span<byte> dest) =>
                {
                    Assert.Equal(48, dest.Length);
                    dest.Fill(0x77);
                }
            };

            byte[] result = ctx.Export("ctx"u8, 48);
            Assert.Equal(48, result.Length);
            AssertExtensions.FilledWith<byte>(0x77, result);
        }

        [Fact]
        public static void DoubleDispose_DoesNotThrow()
        {
            HpkeSenderContract ctx = new(TagSize);
            ctx.Dispose();
            ctx.Dispose();
        }

        [Fact]
        public static void Seal_ByteArray_NullPlaintext_Throws()
        {
            using HpkeSenderContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Seal((byte[])null, new byte[TagSize], aad: null));
        }

        [Fact]
        public static void Seal_ByteArray_NullCiphertext_Throws()
        {
            using HpkeSenderContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Seal(new byte[5], (byte[])null, aad: null));
        }

        [Fact]
        public static void Seal_ByteArray_FunnelsToCore()
        {
            byte[] plaintext = new byte[5];
            byte[] ciphertext = new byte[5 + TagSize];
            byte[] aad = new byte[3];

            using HpkeSenderContract ctx = new(TagSize)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> ct, ReadOnlySpan<byte> a) =>
                {
                    AssertExtensions.Same(plaintext, pt);
                    AssertExtensions.Same(ciphertext, ct);
                    AssertExtensions.Same(aad, a);
                }
            };

            ctx.Seal(plaintext, ciphertext, aad);
        }

        [Fact]
        public static void Seal_ByteArray_Allocated_NullPlaintext_Throws()
        {
            using HpkeSenderContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Seal((byte[])null, aad: null));
        }

        [Fact]
        public static void Seal_ByteArray_Allocated_FunnelsToCore()
        {
            byte[] plaintext = new byte[5];

            using HpkeSenderContract ctx = new(TagSize)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> ct, ReadOnlySpan<byte> a) =>
                {
                    AssertExtensions.Same(plaintext, pt);
                    Assert.Equal(5 + TagSize, ct.Length);
                    ct.Fill(0xBB);
                }
            };

            byte[] result = ctx.Seal(plaintext, aad: null);
            Assert.Equal(5 + TagSize, result.Length);
            AssertExtensions.FilledWith<byte>(0xBB, result);
        }

        [Fact]
        public static void Export_ByteArray_NullExporterContext_Throws()
        {
            using HpkeSenderContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Export((byte[])null, new byte[32]));
        }

        [Fact]
        public static void Export_ByteArray_NullDestination_Throws()
        {
            using HpkeSenderContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Export(new byte[5], (byte[])null));
        }

        [Fact]
        public static void Export_ByteArray_FunnelsToCore()
        {
            byte[] exporterContext = "my context"u8.ToArray();
            byte[] destination = new byte[32];

            using HpkeSenderContract ctx = new(TagSize)
            {
                OnExportCore = (ReadOnlySpan<byte> expCtx, Span<byte> dest) =>
                {
                    AssertExtensions.Same(exporterContext, expCtx);
                    AssertExtensions.Same(destination, dest);
                }
            };

            ctx.Export(exporterContext, destination);
        }

        [Fact]
        public static void Export_ByteArray_Allocated_NullExporterContext_Throws()
        {
            using HpkeSenderContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Export((byte[])null, 32));
        }

        [Fact]
        public static void Export_ByteArray_Allocated_FunnelsToCore()
        {
            byte[] exporterContext = "my context"u8.ToArray();

            using HpkeSenderContract ctx = new(TagSize)
            {
                OnExportCore = (ReadOnlySpan<byte> expCtx, Span<byte> dest) =>
                {
                    AssertExtensions.Same(exporterContext, expCtx);
                    Assert.Equal(48, dest.Length);
                    dest.Fill(0xCC);
                }
            };

            byte[] result = ctx.Export(exporterContext, 48);
            Assert.Equal(48, result.Length);
            AssertExtensions.FilledWith<byte>(0xCC, result);
        }
    }

    public static class HpkeReceiverContractTests
    {
        private const int TagSize = 7;

        [Fact]
        public static void Open_Sequential_Span_Disposed()
        {
            HpkeReceiverContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                ctx.Open(ciphertext: new byte[5 + TagSize], plaintext: new byte[5]));
        }

        [Fact]
        public static void Open_Sequential_Span_Works()
        {
            byte[] ciphertext = new byte[5 + TagSize];
            byte[] plaintext = new byte[5];

            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnOpenCore = (ReadOnlySpan<byte> ct, Span<byte> pt, ReadOnlySpan<byte> aad) =>
                {
                    AssertExtensions.Same(ciphertext, ct);
                    AssertExtensions.Same(plaintext, pt);
                }
            };

            ctx.Open(ciphertext: ciphertext, plaintext: plaintext);
        }

        [Fact]
        public static void Open_Sequential_Allocated_CiphertextTooSmall()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                ctx.Open(new byte[TagSize - 1]));
        }

        [Fact]
        public static void Open_Sequential_Allocated_Disposed()
        {
            HpkeReceiverContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() => ctx.Open(new byte[TagSize]));
        }

        [Fact]
        public static void Open_Sequential_Allocated_Works()
        {
            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnOpenCore = (ReadOnlySpan<byte> ct, Span<byte> pt, ReadOnlySpan<byte> aad) =>
                {
                    Assert.Equal(10 + TagSize, ct.Length);
                    Assert.Equal(10, pt.Length);
                    pt.Fill(0x44);
                }
            };

            byte[] result = ctx.Open(new byte[10 + TagSize]);
            Assert.Equal(10, result.Length);
            AssertExtensions.FilledWith<byte>(0x44, result);
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(-100)]
        public static void Open_Explicit_Span_NegativeSequence_Throws(long sequenceNumber)
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                ctx.Open(sequenceNumber, ciphertext: new byte[TagSize], plaintext: Array.Empty<byte>()));
        }

        [Fact]
        public static void Open_Explicit_Span_Disposed()
        {
            HpkeReceiverContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                ctx.Open(0L, ciphertext: new byte[TagSize], plaintext: Array.Empty<byte>()));
        }

        [Fact]
        public static void Open_Explicit_Span_Works()
        {
            byte[] ciphertext = new byte[5 + TagSize];
            byte[] plaintext = new byte[5];

            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnOpenExplicitCore = (long seq, ReadOnlySpan<byte> ct, Span<byte> pt, ReadOnlySpan<byte> aad) =>
                {
                    Assert.Equal(42L, seq);
                    AssertExtensions.Same(ciphertext, ct);
                    AssertExtensions.Same(plaintext, pt);
                }
            };

            ctx.Open(42L, ciphertext: ciphertext, plaintext: plaintext);
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(-100)]
        public static void Open_Explicit_Allocated_NegativeSequence_Throws(long sequenceNumber)
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                ctx.Open(sequenceNumber, new byte[TagSize]));
        }

        [Fact]
        public static void Open_Explicit_Allocated_CiphertextTooSmall()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                ctx.Open(0L, new byte[TagSize - 1]));
        }

        [Fact]
        public static void Open_Explicit_Allocated_Disposed()
        {
            HpkeReceiverContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() => ctx.Open(0L, new byte[TagSize]));
        }

        [Fact]
        public static void Open_Explicit_Allocated_Works()
        {
            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnOpenExplicitCore = (long seq, ReadOnlySpan<byte> ct, Span<byte> pt, ReadOnlySpan<byte> aad) =>
                {
                    Assert.Equal(99L, seq);
                    Assert.Equal(10 + TagSize, ct.Length);
                    Assert.Equal(10, pt.Length);
                    pt.Fill(0x88);
                }
            };

            byte[] result = ctx.Open(99L, new byte[10 + TagSize]);
            Assert.Equal(10, result.Length);
            AssertExtensions.FilledWith<byte>(0x88, result);
        }

        [Fact]
        public static void Export_Span_ZeroLength_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            AssertExtensions.Throws<ArgumentException>("destination", () =>
                ctx.Export("ctx"u8, Span<byte>.Empty));
        }

        [Fact]
        public static void Export_Span_Disposed()
        {
            HpkeReceiverContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                ctx.Export("ctx"u8, new byte[32]));
        }

        [Fact]
        public static void Export_Span_Works()
        {
            byte[] exporterContext = "my context"u8.ToArray();
            byte[] destination = new byte[32];

            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnExportCore = (ReadOnlySpan<byte> expCtx, Span<byte> dest) =>
                {
                    AssertExtensions.Same(exporterContext, expCtx);
                    AssertExtensions.Same(destination, dest);
                }
            };

            ctx.Export(exporterContext, destination);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(-100)]
        public static void Export_Allocated_InvalidLength_Throws(int length)
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentOutOfRangeException>(() => ctx.Export("ctx"u8, length));
        }

        [Fact]
        public static void Export_Allocated_Disposed()
        {
            HpkeReceiverContract ctx = new(TagSize);
            ctx.Dispose();
            Assert.Throws<ObjectDisposedException>(() => ctx.Export("ctx"u8, 32));
        }

        [Fact]
        public static void Export_Allocated_Works()
        {
            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnExportCore = (ReadOnlySpan<byte> expCtx, Span<byte> dest) =>
                {
                    Assert.Equal(48, dest.Length);
                    dest.Fill(0x66);
                }
            };

            byte[] result = ctx.Export("ctx"u8, 48);
            Assert.Equal(48, result.Length);
            AssertExtensions.FilledWith<byte>(0x66, result);
        }

        [Fact]
        public static void Open_Sequential_ByteArray_NullCiphertext_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Open((byte[])null, new byte[0], aad: null));
        }

        [Fact]
        public static void Open_Sequential_ByteArray_NullPlaintext_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Open(new byte[TagSize], (byte[])null, aad: null));
        }

        [Fact]
        public static void Open_Sequential_ByteArray_FunnelsToCore()
        {
            byte[] ciphertext = new byte[5 + TagSize];
            byte[] plaintext = new byte[5];
            byte[] aad = new byte[3];

            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnOpenCore = (ReadOnlySpan<byte> ct, Span<byte> pt, ReadOnlySpan<byte> a) =>
                {
                    AssertExtensions.Same(ciphertext, ct);
                    AssertExtensions.Same(plaintext, pt);
                    AssertExtensions.Same(aad, a);
                }
            };

            ctx.Open(ciphertext, plaintext, aad);
        }

        [Fact]
        public static void Open_Sequential_ByteArray_Allocated_NullCiphertext_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Open((byte[])null, aad: null));
        }

        [Fact]
        public static void Open_Sequential_ByteArray_Allocated_FunnelsToCore()
        {
            byte[] ciphertext = new byte[10 + TagSize];

            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnOpenCore = (ReadOnlySpan<byte> ct, Span<byte> pt, ReadOnlySpan<byte> a) =>
                {
                    AssertExtensions.Same(ciphertext, ct);
                    Assert.Equal(10, pt.Length);
                    pt.Fill(0xDD);
                }
            };

            byte[] result = ctx.Open(ciphertext, aad: null);
            Assert.Equal(10, result.Length);
            AssertExtensions.FilledWith<byte>(0xDD, result);
        }

        [Fact]
        public static void Open_Explicit_ByteArray_NullCiphertext_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Open(0L, (byte[])null, new byte[0], aad: null));
        }

        [Fact]
        public static void Open_Explicit_ByteArray_NullPlaintext_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Open(0L, new byte[TagSize], (byte[])null, aad: null));
        }

        [Fact]
        public static void Open_Explicit_ByteArray_FunnelsToCore()
        {
            byte[] ciphertext = new byte[5 + TagSize];
            byte[] plaintext = new byte[5];
            byte[] aad = new byte[3];

            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnOpenExplicitCore = (long seq, ReadOnlySpan<byte> ct, Span<byte> pt, ReadOnlySpan<byte> a) =>
                {
                    Assert.Equal(42L, seq);
                    AssertExtensions.Same(ciphertext, ct);
                    AssertExtensions.Same(plaintext, pt);
                    AssertExtensions.Same(aad, a);
                }
            };

            ctx.Open(42L, ciphertext, plaintext, aad);
        }

        [Fact]
        public static void Open_Explicit_ByteArray_Allocated_NullCiphertext_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Open(0L, (byte[])null, aad: null));
        }

        [Fact]
        public static void Open_Explicit_ByteArray_Allocated_FunnelsToCore()
        {
            byte[] ciphertext = new byte[10 + TagSize];

            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnOpenExplicitCore = (long seq, ReadOnlySpan<byte> ct, Span<byte> pt, ReadOnlySpan<byte> a) =>
                {
                    Assert.Equal(99L, seq);
                    AssertExtensions.Same(ciphertext, ct);
                    Assert.Equal(10, pt.Length);
                    pt.Fill(0xEE);
                }
            };

            byte[] result = ctx.Open(99L, ciphertext, aad: null);
            Assert.Equal(10, result.Length);
            AssertExtensions.FilledWith<byte>(0xEE, result);
        }

        [Fact]
        public static void Export_ByteArray_NullExporterContext_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Export((byte[])null, new byte[32]));
        }

        [Fact]
        public static void Export_ByteArray_NullDestination_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Export(new byte[5], (byte[])null));
        }

        [Fact]
        public static void Export_ByteArray_FunnelsToCore()
        {
            byte[] exporterContext = "my context"u8.ToArray();
            byte[] destination = new byte[32];

            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnExportCore = (ReadOnlySpan<byte> expCtx, Span<byte> dest) =>
                {
                    AssertExtensions.Same(exporterContext, expCtx);
                    AssertExtensions.Same(destination, dest);
                }
            };

            ctx.Export(exporterContext, destination);
        }

        [Fact]
        public static void Export_ByteArray_Allocated_NullExporterContext_Throws()
        {
            using HpkeReceiverContract ctx = new(TagSize);
            Assert.Throws<ArgumentNullException>(() =>
                ctx.Export((byte[])null, 32));
        }

        [Fact]
        public static void Export_ByteArray_Allocated_FunnelsToCore()
        {
            byte[] exporterContext = "my context"u8.ToArray();

            using HpkeReceiverContract ctx = new(TagSize)
            {
                OnExportCore = (ReadOnlySpan<byte> expCtx, Span<byte> dest) =>
                {
                    AssertExtensions.Same(exporterContext, expCtx);
                    Assert.Equal(48, dest.Length);
                    dest.Fill(0xFF);
                }
            };

            byte[] result = ctx.Export(exporterContext, 48);
            Assert.Equal(48, result.Length);
            AssertExtensions.FilledWith<byte>(0xFF, result);
        }

        [Fact]
        public static void DoubleDispose_DoesNotThrow()
        {
            HpkeReceiverContract ctx = new(TagSize);
            ctx.Dispose();
            ctx.Dispose();
        }
    }

    internal sealed class HpkeContract : Hpke
    {
        internal ExportKeyCoreCallback OnExportEncapsulationKeyCore { get; set; }
        internal ExportKeyCoreCallback OnExportDecapsulationKeyCore { get; set; }
        internal SealCoreCallback OnSealCore { get; set; }
        internal OpenCoreCallback OnOpenCore { get; set; }
        internal SetupSenderCoreCallback OnSetupSenderCore { get; set; }
        internal SetupSenderPskCoreCallback OnSetupSenderPskCore { get; set; }
        internal SetupSenderAuthCoreCallback OnSetupSenderAuthCore { get; set; }
        internal SetupSenderAuthPskCoreCallback OnSetupSenderAuthPskCore { get; set; }
        internal SetupReceiverCoreCallback OnSetupReceiverCore { get; set; }
        internal SetupReceiverPskCoreCallback OnSetupReceiverPskCore { get; set; }
        internal SetupReceiverAuthCoreCallback OnSetupReceiverAuthCore { get; set; }
        internal SetupReceiverAuthPskCoreCallback OnSetupReceiverAuthPskCore { get; set; }
        internal Action<bool> OnDispose { get; set; }

        public HpkeContract(HpkeSuite suite) : base(suite)
        {
        }

        protected override void ExportEncapsulationKeyCore(Span<byte> destination)
        {
            GetCallback(OnExportEncapsulationKeyCore)(destination);
        }

        protected override void ExportDecapsulationKeyCore(Span<byte> destination)
        {
            GetCallback(OnExportDecapsulationKeyCore)(destination);
        }

        protected override void SealCore(
            ReadOnlySpan<byte> plaintext,
            Span<byte> kemCiphertext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> aad,
            ReadOnlySpan<byte> info)
        {
            GetCallback(OnSealCore)(plaintext, kemCiphertext, ciphertext, aad, info);
        }

        protected override void OpenCore(
            ReadOnlySpan<byte> kemCiphertext,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> aad,
            ReadOnlySpan<byte> info)
        {
            GetCallback(OnOpenCore)(kemCiphertext, ciphertext, plaintext, aad, info);
        }

        protected override HpkeSenderContext SetupSenderCore(Span<byte> kemCiphertext, ReadOnlySpan<byte> info)
        {
            return GetCallback(OnSetupSenderCore)(kemCiphertext, info);
        }

        protected override HpkeSenderContext SetupSenderPskCore(Span<byte> kemCiphertext, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
        {
            return GetCallback(OnSetupSenderPskCore)(kemCiphertext, info, psk, pskId);
        }

        protected override HpkeSenderContext SetupSenderAuthCore(Span<byte> kemCiphertext, Hpke senderKey, ReadOnlySpan<byte> info)
        {
            return GetCallback(OnSetupSenderAuthCore)(kemCiphertext, senderKey, info);
        }

        protected override HpkeSenderContext SetupSenderAuthPskCore(Span<byte> kemCiphertext, Hpke senderKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
        {
            return GetCallback(OnSetupSenderAuthPskCore)(kemCiphertext, senderKey, info, psk, pskId);
        }

        protected override HpkeReceiverContext SetupReceiverCore(ReadOnlySpan<byte> kemCiphertext, ReadOnlySpan<byte> info)
        {
            return GetCallback(OnSetupReceiverCore)(kemCiphertext, info);
        }

        protected override HpkeReceiverContext SetupReceiverPskCore(ReadOnlySpan<byte> kemCiphertext, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
        {
            return GetCallback(OnSetupReceiverPskCore)(kemCiphertext, info, psk, pskId);
        }

        protected override HpkeReceiverContext SetupReceiverAuthCore(ReadOnlySpan<byte> kemCiphertext, Hpke senderKey, ReadOnlySpan<byte> info)
        {
            return GetCallback(OnSetupReceiverAuthCore)(kemCiphertext, senderKey, info);
        }

        protected override HpkeReceiverContext SetupReceiverAuthPskCore(ReadOnlySpan<byte> kemCiphertext, Hpke senderKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
        {
            return GetCallback(OnSetupReceiverAuthPskCore)(kemCiphertext, senderKey, info, psk, pskId);
        }

        protected override void Dispose(bool disposing)
        {
            OnDispose?.Invoke(disposing);
            base.Dispose(disposing);
        }

        private T GetCallback<T>(T callback, [CallerMemberName] string caller = null) where T : Delegate
        {
            return callback ?? throw new XunitException($"Unexpected call to {caller}.");
        }

        internal delegate void ExportKeyCoreCallback(Span<byte> destination);
        internal delegate void SealCoreCallback(ReadOnlySpan<byte> plaintext, Span<byte> kemCiphertext, Span<byte> ciphertext, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info);
        internal delegate void OpenCoreCallback(ReadOnlySpan<byte> kemCiphertext, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info);
        internal delegate HpkeSenderContext SetupSenderCoreCallback(Span<byte> kemCiphertext, ReadOnlySpan<byte> info);
        internal delegate HpkeSenderContext SetupSenderPskCoreCallback(Span<byte> kemCiphertext, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId);
        internal delegate HpkeSenderContext SetupSenderAuthCoreCallback(Span<byte> kemCiphertext, Hpke senderKey, ReadOnlySpan<byte> info);
        internal delegate HpkeSenderContext SetupSenderAuthPskCoreCallback(Span<byte> kemCiphertext, Hpke senderKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId);
        internal delegate HpkeReceiverContext SetupReceiverCoreCallback(ReadOnlySpan<byte> kemCiphertext, ReadOnlySpan<byte> info);
        internal delegate HpkeReceiverContext SetupReceiverPskCoreCallback(ReadOnlySpan<byte> kemCiphertext, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId);
        internal delegate HpkeReceiverContext SetupReceiverAuthCoreCallback(ReadOnlySpan<byte> kemCiphertext, Hpke senderKey, ReadOnlySpan<byte> info);
        internal delegate HpkeReceiverContext SetupReceiverAuthPskCoreCallback(ReadOnlySpan<byte> kemCiphertext, Hpke senderKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId);
    }

    internal sealed class HpkeSenderContract : HpkeSenderContext
    {
        private readonly int _tagSize;

        internal SealCoreCallback OnSealCore { get; set; }
        internal ExportCoreCallback OnExportCore { get; set; }

        public HpkeSenderContract(int tagSize)
        {
            _tagSize = tagSize;
        }

        protected override void SealCore(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> aad)
        {
            GetCallback(OnSealCore)(plaintext, ciphertext, aad);
        }

        protected override void ExportCore(ReadOnlySpan<byte> exporterContext, Span<byte> destination)
        {
            GetCallback(OnExportCore)(exporterContext, destination);
        }

        protected override int GetAeadTagSizeInBytes() => _tagSize;

        private T GetCallback<T>(T callback, [CallerMemberName] string caller = null) where T : Delegate
        {
            return callback ?? throw new XunitException($"Unexpected call to {caller}.");
        }

        internal delegate void SealCoreCallback(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> aad);
        internal delegate void ExportCoreCallback(ReadOnlySpan<byte> exporterContext, Span<byte> destination);
    }

    internal sealed class HpkeReceiverContract : HpkeReceiverContext
    {
        private readonly int _tagSize;

        internal OpenCoreCallback OnOpenCore { get; set; }
        internal OpenExplicitCoreCallback OnOpenExplicitCore { get; set; }
        internal ExportCoreCallback OnExportCore { get; set; }

        public HpkeReceiverContract(int tagSize)
        {
            _tagSize = tagSize;
        }

        protected override void OpenCore(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad)
        {
            GetCallback(OnOpenCore)(ciphertext, plaintext, aad);
        }

        protected override void OpenCore(long sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad)
        {
            GetCallback(OnOpenExplicitCore)(sequenceNumber, ciphertext, plaintext, aad);
        }

        protected override void ExportCore(ReadOnlySpan<byte> exporterContext, Span<byte> destination)
        {
            GetCallback(OnExportCore)(exporterContext, destination);
        }

        protected override int GetAeadTagSizeInBytes() => _tagSize;

        private T GetCallback<T>(T callback, [CallerMemberName] string caller = null) where T : Delegate
        {
            return callback ?? throw new XunitException($"Unexpected call to {caller}.");
        }

        internal delegate void OpenCoreCallback(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad);
        internal delegate void OpenExplicitCoreCallback(long sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad);
        internal delegate void ExportCoreCallback(ReadOnlySpan<byte> exporterContext, Span<byte> destination);
    }
}
