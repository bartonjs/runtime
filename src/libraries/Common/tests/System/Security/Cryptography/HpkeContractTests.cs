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
        public static void Seal_Span_WrongEncapsulatedKeySize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] plaintext = new byte[10];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
                hpke.Seal(plaintext: plaintext, encapsulatedKey: new byte[s_suite.EncapsulatedKeySizeInBytes - 1], ciphertext: ciphertext));

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
                hpke.Seal(plaintext: plaintext, encapsulatedKey: new byte[s_suite.EncapsulatedKeySizeInBytes + 1], ciphertext: ciphertext));
        }

        [Fact]
        public static void Seal_Span_WrongCiphertextSize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] plaintext = new byte[10];
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                hpke.Seal(plaintext: plaintext, encapsulatedKey: encapsulatedKey, ciphertext: new byte[10 + s_suite.AeadTagSizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                hpke.Seal(plaintext: plaintext, encapsulatedKey: encapsulatedKey, ciphertext: new byte[10 + s_suite.AeadTagSizeInBytes + 1]));
        }

        [Fact]
        public static void Seal_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.Seal(
                    plaintext: new byte[10],
                    encapsulatedKey: new byte[s_suite.EncapsulatedKeySizeInBytes],
                    ciphertext: new byte[10 + s_suite.AeadTagSizeInBytes]));
        }

        [Fact]
        public static void Seal_Span_Works()
        {
            byte[] plaintext = new byte[10];
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            using HpkeContract hpke = new(s_suite)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> kemDest, Span<byte> ctDest, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(plaintext, pt);
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    AssertExtensions.Same(ciphertext, ctDest);
                }
            };

            hpke.Seal(plaintext: plaintext, encapsulatedKey: encapsulatedKey, ciphertext: ciphertext);
        }

        [Fact]
        public static void Seal_Allocated_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() => hpke.Seal(new byte[10], out byte[] _, out byte[] _));
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

            hpke.Seal(plaintext, out byte[] encapsulatedKey, out byte[] ciphertext);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, encapsulatedKey.Length);
            Assert.Equal(plaintext.Length + s_suite.AeadTagSizeInBytes, ciphertext.Length);
            AssertExtensions.FilledWith<byte>(0x11, encapsulatedKey);
            AssertExtensions.FilledWith<byte>(0x22, ciphertext);
        }

        [Fact]
        public static void Open_Span_WrongEncapsulatedKeySize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];
            byte[] plaintext = new byte[10];

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
                hpke.Open(
                    encapsulatedKey: new byte[s_suite.EncapsulatedKeySizeInBytes - 1],
                    ciphertext: ciphertext,
                    plaintext: plaintext));

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
                hpke.Open(
                    encapsulatedKey: new byte[s_suite.EncapsulatedKeySizeInBytes + 1],
                    ciphertext: ciphertext,
                    plaintext: plaintext));
        }

        [Fact]
        public static void Open_Span_CiphertextTooSmall()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                hpke.Open(encapsulatedKey: encapsulatedKey, ciphertext: new byte[s_suite.AeadTagSizeInBytes - 1], plaintext: Array.Empty<byte>()));
        }

        [Fact]
        public static void Open_Span_WrongPlaintextSize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            AssertExtensions.Throws<ArgumentException>("plaintext", () =>
                hpke.Open(encapsulatedKey: encapsulatedKey, ciphertext: ciphertext, plaintext: new byte[10 - 1]));

            AssertExtensions.Throws<ArgumentException>("plaintext", () =>
                hpke.Open(encapsulatedKey: encapsulatedKey, ciphertext: ciphertext, plaintext: new byte[10 + 1]));
        }

        [Fact]
        public static void Open_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.Open(
                    encapsulatedKey: new byte[s_suite.EncapsulatedKeySizeInBytes],
                    ciphertext: new byte[s_suite.AeadTagSizeInBytes],
                    plaintext: Array.Empty<byte>()));
        }

        [Fact]
        public static void Open_Span_Works()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];
            byte[] plaintext = new byte[10];

            using HpkeContract hpke = new(s_suite)
            {
                OnOpenCore = (ReadOnlySpan<byte> kemDest, ReadOnlySpan<byte> ctSrc, Span<byte> ptDest, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    AssertExtensions.Same(ciphertext, ctSrc);
                    AssertExtensions.Same(plaintext, ptDest);
                }
            };

            hpke.Open(encapsulatedKey: encapsulatedKey, ciphertext: ciphertext, plaintext: plaintext);
        }

        [Fact]
        public static void Open_Allocated_WrongEncapsulatedKeySize()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
                hpke.Open(new byte[s_suite.EncapsulatedKeySizeInBytes - 1], ciphertext));

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
                hpke.Open(new byte[s_suite.EncapsulatedKeySizeInBytes + 1], ciphertext));
        }

        [Fact]
        public static void Open_Allocated_CiphertextTooSmall()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];

            AssertExtensions.Throws<ArgumentException>("ciphertext", () =>
                hpke.Open(encapsulatedKey, new byte[s_suite.AeadTagSizeInBytes - 1]));
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
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            using HpkeContract hpke = new(s_suite)
            {
                OnOpenCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> ctSrc, Span<byte> ptDest, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    AssertExtensions.Same(ciphertext, ctSrc);
                    Assert.Equal(10, ptDest.Length);
                    ptDest.Fill(0x55);
                }
            };

            byte[] result = hpke.Open(encapsulatedKey, ciphertext);
            Assert.Equal(10, result.Length);
            AssertExtensions.FilledWith<byte>(0x55, result);
        }

        [Fact]
        public static void SetupSender_Span_WrongEncapsulatedKeySize()
        {
            using HpkeContract hpke = new(s_suite);

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
                hpke.SetupSender(encapsulatedKey: new byte[s_suite.EncapsulatedKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
                hpke.SetupSender(encapsulatedKey: new byte[s_suite.EncapsulatedKeySizeInBytes + 1]));
        }

        [Fact]
        public static void SetupSender_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSender(encapsulatedKey: new byte[s_suite.EncapsulatedKeySizeInBytes]));
        }

        [Fact]
        public static void SetupSender_Span_Works()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderCore = (Span<byte> kemDest, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    return returnedCtx;
                }
            };

            HpkeSender ctx = hpke.SetupSender(encapsulatedKey: encapsulatedKey);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Allocated_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() => hpke.SetupSender(out byte[] _));
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

            HpkeSender ctx = hpke.SetupSender(out byte[] encapsulatedKey);
            Assert.Same(returnedCtx, ctx);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, encapsulatedKey.Length);
            AssertExtensions.FilledWith<byte>(0x33, encapsulatedKey);
        }

        [Fact]
        public static void SetupReceiver_WrongEncapsulatedKeySize()
        {
            using HpkeContract hpke = new(s_suite);

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
                hpke.SetupReceiver(new byte[s_suite.EncapsulatedKeySizeInBytes - 1]));

            AssertExtensions.Throws<ArgumentException>("encapsulatedKey", () =>
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
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> info) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    return returnedCtx;
                }
            };

            HpkeReceiver ctx = hpke.SetupReceiver(encapsulatedKey);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void Seal_ByteArray_FunnelsToCore()
        {
            byte[] plaintext = new byte[10];
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];
            byte[] aad = new byte[3];
            byte[] info = new byte[4];

            using HpkeContract hpke = new(s_suite)
            {
                OnSealCore = (ReadOnlySpan<byte> pt, Span<byte> kemDest, Span<byte> ctDest, ReadOnlySpan<byte> a, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(plaintext, pt);
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    AssertExtensions.Same(ciphertext, ctDest);
                    AssertExtensions.Same(aad, a);
                    AssertExtensions.Same(info, i);
                }
            };

            hpke.Seal(plaintext, encapsulatedKey, ciphertext, aad, info);
        }

        [Fact]
        public static void Seal_ByteArray_Allocated_NullPlaintext_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.Seal((byte[])null, out byte[] _, out byte[] _, aad: null, info: null));
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

            hpke.Seal(plaintext, out byte[] encapsulatedKey, out byte[] ciphertext, aad: null, info: null);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, encapsulatedKey.Length);
            AssertExtensions.FilledWith<byte>(0x11, encapsulatedKey);
            Assert.Equal(plaintext.Length + s_suite.AeadTagSizeInBytes, ciphertext.Length);
            AssertExtensions.FilledWith<byte>(0x22, ciphertext);
        }

        [Fact]
        public static void Open_ByteArray_FunnelsToCore()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];
            byte[] plaintext = new byte[10];
            byte[] aad = new byte[3];
            byte[] info = new byte[4];

            using HpkeContract hpke = new(s_suite)
            {
                OnOpenCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> ctSrc, Span<byte> ptDest, ReadOnlySpan<byte> a, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    AssertExtensions.Same(ciphertext, ctSrc);
                    AssertExtensions.Same(plaintext, ptDest);
                    AssertExtensions.Same(aad, a);
                    AssertExtensions.Same(info, i);
                }
            };

            hpke.Open(encapsulatedKey, ciphertext, plaintext, aad, info);
        }

        [Fact]
        public static void Open_ByteArray_Allocated_NullEncapsulatedKey_Throws()
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
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] ciphertext = new byte[10 + s_suite.AeadTagSizeInBytes];

            using HpkeContract hpke = new(s_suite)
            {
                OnOpenCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> ctSrc, Span<byte> ptDest, ReadOnlySpan<byte> a, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    AssertExtensions.Same(ciphertext, ctSrc);
                    Assert.Equal(10, ptDest.Length);
                    ptDest.Fill(0xAA);
                }
            };

            byte[] result = hpke.Open(encapsulatedKey, ciphertext, aad: null, info: null);
            Assert.Equal(10, result.Length);
            AssertExtensions.FilledWith<byte>(0xAA, result);
        }

        [Fact]
        public static void SetupSender_ByteArray_FunnelsToCore()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[4];
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderCore = (Span<byte> kemDest, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeSender ctx = hpke.SetupSender(encapsulatedKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_ByteArray_NullEncapsulatedKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupReceiver((byte[])null, info: null));
        }

        [Fact]
        public static void SetupReceiver_ByteArray_FunnelsToCore()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[4];
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeReceiver ctx = hpke.SetupReceiver(encapsulatedKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Psk_Span_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupSenderPsk(ReadOnlySpan<byte>.Empty, new byte[] { 1 }, encapsulatedKey.AsSpan()));
        }

        [Fact]
        public static void SetupSender_Psk_Span_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupSenderPsk(new byte[] { 1 }, ReadOnlySpan<byte>.Empty, encapsulatedKey.AsSpan()));
        }

        [Fact]
        public static void SetupSender_Psk_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderPsk(new byte[] { 1 }, new byte[] { 2 }, encapsulatedKey.AsSpan()));
        }

        [Fact]
        public static void SetupSender_Psk_Span_Works()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderPskCore = (Span<byte> kemDest, ReadOnlySpan<byte> info, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeSender ctx = hpke.SetupSenderPsk(psk, pskId, encapsulatedKey.AsSpan());
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupSenderPsk(ReadOnlySpan<byte>.Empty, new byte[] { 1 }, out _));
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupSenderPsk(new byte[] { 1 }, ReadOnlySpan<byte>.Empty, out _));
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderPsk(new byte[] { 1 }, new byte[] { 2 }, out byte[] _));
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

            HpkeSender ctx = hpke.SetupSenderPsk(psk, pskId, out byte[] encapsulatedKey);
            Assert.Same(returnedCtx, ctx);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, encapsulatedKey.Length);
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_NullPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupSenderPsk((byte[])null, new byte[] { 1 }, out byte[] _));
        }

        [Fact]
        public static void SetupSender_Psk_Allocated_NullPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupSenderPsk(new byte[] { 1 }, (byte[])null, out byte[] _));
        }

        [Fact]
        public static void SetupSender_Psk_ByteArray_FunnelsToCore()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderPskCore = (Span<byte> kemDest, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeSender ctx = hpke.SetupSenderPsk(psk, pskId, encapsulatedKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_Psk_Span_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupReceiverPsk(new ReadOnlySpan<byte>(encapsulatedKey), ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupReceiver_Psk_Span_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupReceiverPsk(new ReadOnlySpan<byte>(encapsulatedKey), new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void SetupReceiver_Psk_Span_Disposed()
        {
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverPsk(new ReadOnlySpan<byte>(encapsulatedKey), new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupReceiver_Psk_Span_Works()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverPskCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> info, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeReceiver ctx = hpke.SetupReceiverPsk(new ReadOnlySpan<byte>(encapsulatedKey), psk, pskId);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_Psk_ByteArray_NullPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupReceiverPsk(encapsulatedKey, (byte[])null, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupReceiver_Psk_ByteArray_NullPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupReceiverPsk(encapsulatedKey, new byte[] { 1 }, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_Psk_ByteArray_NullEncapsulatedKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            Assert.Throws<ArgumentNullException>(() =>
                hpke.SetupReceiverPsk((byte[])null, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupReceiver_Psk_ByteArray_FunnelsToCore()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverPskCore = (ReadOnlySpan<byte> kemSrc, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeReceiver ctx = hpke.SetupReceiverPsk(encapsulatedKey, psk, pskId, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Auth_Span_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupSenderAuth(encapsulatedKey.AsSpan(), null));
        }

        [Fact]
        public static void SetupSender_Auth_Span_Disposed()
        {
            using HpkeContract senderKey = new(s_suite);
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderAuth(encapsulatedKey.AsSpan(), senderKey));
        }

        [Fact]
        public static void SetupSender_Auth_Span_SenderDisposed()
        {
            using HpkeContract hpke = new(s_suite);
            HpkeContract senderKey = new(s_suite);
            senderKey.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderAuth(encapsulatedKey.AsSpan(), senderKey));
        }

        [Fact]
        public static void SetupSender_Auth_Span_SuiteMismatch_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_otherSuite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("senderKey", () =>
                hpke.SetupSenderAuth(encapsulatedKey.AsSpan(), senderKey));
        }

        [Fact]
        public static void SetupSender_Auth_Span_Works()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[] { 1, 2, 3 };
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeSender ctx = hpke.SetupSenderAuth(encapsulatedKey.AsSpan(), senderKey, info);
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

            HpkeSender ctx = hpke.SetupSenderAuth(out byte[] encapsulatedKey, senderKey, default(ReadOnlySpan<byte>));
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, encapsulatedKey.Length);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_Auth_ByteArray_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupSenderAuth(encapsulatedKey, null, (byte[])null));
        }

        [Fact]
        public static void SetupSender_Auth_Allocated_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupSenderAuth(out byte[] _, (Hpke)null, (byte[])null));
        }

        [Fact]
        public static void SetupSender_Auth_ByteArray_FunnelsToCore()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeSender ctx = hpke.SetupSenderAuth(encapsulatedKey, senderKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(encapsulatedKey), null));
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_SenderDisposed()
        {
            using HpkeContract hpke = new(s_suite);
            HpkeContract senderKey = new(s_suite);
            senderKey.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(encapsulatedKey), senderKey));
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_Disposed()
        {
            using HpkeContract senderKey = new(s_suite);
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(encapsulatedKey), senderKey));
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_SuiteMismatch_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_otherSuite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("senderKey", () =>
                hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(encapsulatedKey), senderKey));
        }

        [Fact]
        public static void SetupReceiver_Auth_Span_Works()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[] { 9 };
            using HpkeContract senderKey = new(s_suite);
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverAuthCore = (ReadOnlySpan<byte> kemSrc, Hpke sender, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeReceiver ctx = hpke.SetupReceiverAuth(new ReadOnlySpan<byte>(encapsulatedKey), senderKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_Auth_ByteArray_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupReceiverAuth(encapsulatedKey, null, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_Auth_ByteArray_NullEncapsulatedKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            AssertExtensions.Throws<ArgumentNullException>("encapsulatedKey", () =>
                hpke.SetupReceiverAuth((byte[])null, senderKey, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_Auth_ByteArray_FunnelsToCore()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverAuthCore = (ReadOnlySpan<byte> kemSrc, Hpke sender, ReadOnlySpan<byte> i) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    return returnedCtx;
                }
            };

            HpkeReceiver ctx = hpke.SetupReceiverAuth(encapsulatedKey, senderKey, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupSenderAuthPsk(encapsulatedKey.AsSpan(), senderKey, ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupSenderAuthPsk(encapsulatedKey.AsSpan(), senderKey, new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_Disposed()
        {
            using HpkeContract senderKey = new(s_suite);
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderAuthPsk(encapsulatedKey.AsSpan(), senderKey, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_SenderDisposed()
        {
            using HpkeContract hpke = new(s_suite);
            HpkeContract senderKey = new(s_suite);
            senderKey.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupSenderAuthPsk(encapsulatedKey.AsSpan(), senderKey, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupSender_AuthPsk_Span_Works()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthPskCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeSender ctx = hpke.SetupSenderAuthPsk(encapsulatedKey.AsSpan(), senderKey, psk, pskId, info);
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

            HpkeSender ctx = hpke.SetupSenderAuthPsk(out byte[] encapsulatedKey, senderKey, psk, pskId);
            Assert.Equal(s_suite.EncapsulatedKeySizeInBytes, encapsulatedKey.Length);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupSender_AuthPsk_ByteArray_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupSenderAuthPsk(encapsulatedKey, null, new byte[] { 1 }, new byte[] { 2 }, (byte[])null));
        }

        [Fact]
        public static void SetupSender_AuthPsk_ByteArray_NullPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            AssertExtensions.Throws<ArgumentNullException>("psk", () =>
                hpke.SetupSenderAuthPsk(out byte[] _, senderKey, null, new byte[] { 2 }, (byte[])null));
        }

        [Fact]
        public static void SetupSender_AuthPsk_ByteArray_NullPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            AssertExtensions.Throws<ArgumentNullException>("pskId", () =>
                hpke.SetupSenderAuthPsk(out byte[] _, senderKey, new byte[] { 1 }, null, (byte[])null));
        }

        [Fact]
        public static void SetupSender_AuthPsk_ByteArray_FunnelsToCore()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeSenderContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupSenderAuthPskCore = (Span<byte> kemDest, Hpke sender, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemDest);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeSender ctx = hpke.SetupSenderAuthPsk(encapsulatedKey, senderKey, psk, pskId, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_EmptyPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("psk", () =>
                hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(encapsulatedKey), senderKey, ReadOnlySpan<byte>.Empty, new byte[] { 1 }));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_EmptyPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentException>("pskId", () =>
                hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(encapsulatedKey), senderKey, new byte[] { 1 }, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_Disposed()
        {
            using HpkeContract senderKey = new(s_suite);
            HpkeContract hpke = new(s_suite);
            hpke.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(encapsulatedKey), senderKey, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_SenderDisposed()
        {
            using HpkeContract hpke = new(s_suite);
            HpkeContract senderKey = new(s_suite);
            senderKey.Dispose();
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            Assert.Throws<ObjectDisposedException>(() =>
                hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(encapsulatedKey), senderKey, new byte[] { 1 }, new byte[] { 2 }));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_Span_Works()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverAuthPskCore = (ReadOnlySpan<byte> kemSrc, Hpke sender, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeReceiver ctx = hpke.SetupReceiverAuthPsk(new ReadOnlySpan<byte>(encapsulatedKey), senderKey, psk, pskId, info);
            Assert.Same(returnedCtx, ctx);
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_ByteArray_NullSenderKey_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("senderKey", () =>
                hpke.SetupReceiverAuthPsk(encapsulatedKey, null, new byte[] { 1 }, new byte[] { 2 }, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_ByteArray_NullPsk_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("psk", () =>
                hpke.SetupReceiverAuthPsk(encapsulatedKey, senderKey, null, new byte[] { 2 }, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_ByteArray_NullPskId_Throws()
        {
            using HpkeContract hpke = new(s_suite);
            using HpkeContract senderKey = new(s_suite);
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            AssertExtensions.Throws<ArgumentNullException>("pskId", () =>
                hpke.SetupReceiverAuthPsk(encapsulatedKey, senderKey, new byte[] { 1 }, null, (byte[])null));
        }

        [Fact]
        public static void SetupReceiver_AuthPsk_ByteArray_FunnelsToCore()
        {
            byte[] encapsulatedKey = new byte[s_suite.EncapsulatedKeySizeInBytes];
            byte[] psk = new byte[] { 1, 2, 3 };
            byte[] pskId = new byte[] { 4, 5 };
            byte[] info = new byte[] { 6 };
            using HpkeContract senderKey = new(s_suite);
            HpkeReceiverContract returnedCtx = new(7);

            using HpkeContract hpke = new(s_suite)
            {
                OnSetupReceiverAuthPskCore = (ReadOnlySpan<byte> kemSrc, Hpke sender, ReadOnlySpan<byte> i, ReadOnlySpan<byte> p, ReadOnlySpan<byte> pid) =>
                {
                    AssertExtensions.Same(encapsulatedKey, kemSrc);
                    Assert.Same(senderKey, sender);
                    AssertExtensions.Same(info, i);
                    AssertExtensions.Same(psk, p);
                    AssertExtensions.Same(pskId, pid);
                    return returnedCtx;
                }
            };

            HpkeReceiver ctx = hpke.SetupReceiverAuthPsk(encapsulatedKey, senderKey, psk, pskId, info);
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
            Span<byte> encapsulatedKey,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> aad,
            ReadOnlySpan<byte> info)
        {
            GetCallback(OnSealCore)(plaintext, encapsulatedKey, ciphertext, aad, info);
        }

        protected override void OpenCore(
            ReadOnlySpan<byte> encapsulatedKey,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> aad,
            ReadOnlySpan<byte> info)
        {
            GetCallback(OnOpenCore)(encapsulatedKey, ciphertext, plaintext, aad, info);
        }

        protected override HpkeSender SetupSenderCore(Span<byte> encapsulatedKey, ReadOnlySpan<byte> info)
        {
            return GetCallback(OnSetupSenderCore)(encapsulatedKey, info);
        }

        protected override HpkeSender SetupSenderPskCore(Span<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
        {
            return GetCallback(OnSetupSenderPskCore)(encapsulatedKey, info, psk, pskId);
        }

        protected override HpkeSender SetupSenderAuthCore(Span<byte> encapsulatedKey, Hpke senderKey, ReadOnlySpan<byte> info)
        {
            return GetCallback(OnSetupSenderAuthCore)(encapsulatedKey, senderKey, info);
        }

        protected override HpkeSender SetupSenderAuthPskCore(Span<byte> encapsulatedKey, Hpke senderKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
        {
            return GetCallback(OnSetupSenderAuthPskCore)(encapsulatedKey, senderKey, info, psk, pskId);
        }

        protected override HpkeReceiver SetupReceiverCore(ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info)
        {
            return GetCallback(OnSetupReceiverCore)(encapsulatedKey, info);
        }

        protected override HpkeReceiver SetupReceiverPskCore(ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
        {
            return GetCallback(OnSetupReceiverPskCore)(encapsulatedKey, info, psk, pskId);
        }

        protected override HpkeReceiver SetupReceiverAuthCore(ReadOnlySpan<byte> encapsulatedKey, Hpke senderKey, ReadOnlySpan<byte> info)
        {
            return GetCallback(OnSetupReceiverAuthCore)(encapsulatedKey, senderKey, info);
        }

        protected override HpkeReceiver SetupReceiverAuthPskCore(ReadOnlySpan<byte> encapsulatedKey, Hpke senderKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
        {
            return GetCallback(OnSetupReceiverAuthPskCore)(encapsulatedKey, senderKey, info, psk, pskId);
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
        internal delegate void SealCoreCallback(ReadOnlySpan<byte> plaintext, Span<byte> encapsulatedKey, Span<byte> ciphertext, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info);
        internal delegate void OpenCoreCallback(ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> info);
        internal delegate HpkeSender SetupSenderCoreCallback(Span<byte> encapsulatedKey, ReadOnlySpan<byte> info);
        internal delegate HpkeSender SetupSenderPskCoreCallback(Span<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId);
        internal delegate HpkeSender SetupSenderAuthCoreCallback(Span<byte> encapsulatedKey, Hpke senderKey, ReadOnlySpan<byte> info);
        internal delegate HpkeSender SetupSenderAuthPskCoreCallback(Span<byte> encapsulatedKey, Hpke senderKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId);
        internal delegate HpkeReceiver SetupReceiverCoreCallback(ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info);
        internal delegate HpkeReceiver SetupReceiverPskCoreCallback(ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId);
        internal delegate HpkeReceiver SetupReceiverAuthCoreCallback(ReadOnlySpan<byte> encapsulatedKey, Hpke senderKey, ReadOnlySpan<byte> info);
        internal delegate HpkeReceiver SetupReceiverAuthPskCoreCallback(ReadOnlySpan<byte> encapsulatedKey, Hpke senderKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId);
    }

    internal sealed class HpkeSenderContract : HpkeSender
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

    internal sealed class HpkeReceiverContract : HpkeReceiver
    {
        private readonly int _tagSize;

        internal OpenCoreCallback OnOpenCore { get; set; }
        internal ExportCoreCallback OnExportCore { get; set; }

        public HpkeReceiverContract(int tagSize)
        {
            _tagSize = tagSize;
        }

        protected override void OpenCore(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad)
        {
            GetCallback(OnOpenCore)(ciphertext, plaintext, aad);
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
        internal delegate void ExportCoreCallback(ReadOnlySpan<byte> exporterContext, Span<byte> destination);
    }
}
