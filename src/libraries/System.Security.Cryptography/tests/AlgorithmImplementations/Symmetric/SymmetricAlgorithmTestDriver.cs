// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Symmetric
{
    public abstract partial class SymmetricAlgorithmTestDriver<TCapabilities>
        where TCapabilities : ISymmetricAlgorithmCapabilities<TCapabilities>
    {
        // ASCII/UTF-8 of
        // This is a sentence that is longer than a block, it ensures that multi-block functions work.
        private static ReadOnlySpan<byte> Input0Span => new byte[]
        {
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
            0x61, 0x20, 0x73, 0x65, 0x6E, 0x74, 0x65, 0x6E,
            0x63, 0x65, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20,
            0x69, 0x73, 0x20, 0x6C, 0x6F, 0x6E, 0x67, 0x65,
            0x72, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x61,
            0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x2C, 0x20,
            0x69, 0x74, 0x20, 0x65, 0x6E, 0x73, 0x75, 0x72,
            0x65, 0x73, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20,
            0x6D, 0x75, 0x6C, 0x74, 0x69, 0x2D, 0x62, 0x6C,
            0x6F, 0x63, 0x6B, 0x20, 0x66, 0x75, 0x6E, 0x63,
            0x74, 0x69, 0x6F, 0x6E, 0x73, 0x20, 0x77, 0x6F,
            0x72, 0x6B, 0x2E,
        };

        private static readonly byte[] s_input0 = Input0Span.ToArray();

        public static object[][] TestModes { get; } = BuildTestModesFromCapabilities().ToArray();

        private static IEnumerable<object[]> BuildTestModesFromCapabilities()
        {
            yield return new object[] { SymmetricTestModes.TransformFinalBlock };

            if (TCapabilities.CanReadKeyProperty)
            {
                yield return new object[] { SymmetricTestModes.TransformFinalBlockParameterized };
            }

            yield return new object[] { SymmetricTestModes.CryptoStream };

            if (TCapabilities.HasOneShots)
            {
                yield return new object[] { SymmetricTestModes.OneShotArray };
                yield return new object[] { SymmetricTestModes.OneShotSpan };
            }
        }

        public static bool MissingOneShots => !TCapabilities.HasOneShots;

        protected abstract SymmetricAlgorithm Create();
        protected abstract IEnumerable<SymmetricKnownValueTestCase> EnumerateKnownValues();

        private static byte[] Decrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> cipherText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            SymmetricTestModes testMode)
        {
            switch (testMode)
            {
                case SymmetricTestModes.TransformFinalBlock:
                    return TransformFinalBlockDecrypt(key, cipherText, iv, cipherMode, paddingMode);
                case SymmetricTestModes.TransformFinalBlockParameterized:
                    return TransformFinalBlockParameterizedDecrypt(key, cipherText, iv, cipherMode, paddingMode);
                case SymmetricTestModes.CryptoStream:
                    return CryptoStreamDecrypt(key, cipherText, iv, cipherMode, paddingMode);
                case SymmetricTestModes.OneShotArray:
                    return OneShotArrayDecrypt(key, cipherText, iv, cipherMode, paddingMode);
                case SymmetricTestModes.OneShotSpan:
                    return OneShotSpanDecrypt(key, cipherText, iv, cipherMode, paddingMode);
                default:
                    throw new ArgumentOutOfRangeException(
                        nameof(testMode),
                        testMode,
                        $"'{testMode}' is not a handled encryption mode");
            }
        }

        private static byte[] Encrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> plainText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            SymmetricTestModes testMode)
        {
            switch (testMode)
            {
                case SymmetricTestModes.TransformFinalBlock:
                    return TransformFinalBlockEncrypt(key, plainText, iv, cipherMode, paddingMode);
                case SymmetricTestModes.TransformFinalBlockParameterized:
                    return TransformFinalBlockParameterizedEncrypt(key, plainText, iv, cipherMode, paddingMode);
                case SymmetricTestModes.CryptoStream:
                    return CryptoStreamEncrypt(key, plainText, iv, cipherMode, paddingMode);
                case SymmetricTestModes.OneShotArray:
                    return OneShotArrayEncrypt(key, plainText, iv, cipherMode, paddingMode);
                case SymmetricTestModes.OneShotSpan:
                    return OneShotSpanEncrypt(key, plainText, iv, cipherMode, paddingMode);
                default:
                    throw new ArgumentOutOfRangeException(
                        nameof(testMode),
                        testMode,
                        $"'{testMode}' is not a handled encryption mode");
            }
        }

        private static byte[] TransformFinalBlockDecrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> cipherText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            key.IV = iv;
            key.Mode = cipherMode;
            key.Padding = paddingMode;

            using (ICryptoTransform transform = key.CreateDecryptor())
            {
                byte[] first = transform.TransformFinalBlock(cipherText.Array!, cipherText.Offset, cipherText.Count);

                if (transform.CanReuseTransform)
                {
                    byte[] second =
                        transform.TransformFinalBlock(cipherText.Array, cipherText.Offset, cipherText.Count);

                    AssertExtensions.SequenceEqual(first, second);
                }

                return first;
            }
        }

        private static byte[] TransformFinalBlockParameterizedDecrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> cipherText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            key.Mode = cipherMode;
            key.Padding = paddingMode;

            using (ICryptoTransform transform = key.CreateDecryptor(key.Key, iv))
            {
                byte[] first = transform.TransformFinalBlock(cipherText.Array!, cipherText.Offset, cipherText.Count);

                if (transform.CanReuseTransform)
                {
                    byte[] second =
                        transform.TransformFinalBlock(cipherText.Array, cipherText.Offset, cipherText.Count);

                    AssertExtensions.SequenceEqual(first, second);
                }

                return first;
            }
        }

        private static byte[] TransformFinalBlockEncrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> plainText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            key.IV = iv;
            key.Mode = cipherMode;
            key.Padding = paddingMode;

            using (ICryptoTransform transform = key.CreateEncryptor())
            {
                byte[] first = transform.TransformFinalBlock(plainText.Array!, plainText.Offset, plainText.Count);

                if (transform.CanReuseTransform)
                {
                    byte[] second =
                        transform.TransformFinalBlock(plainText.Array, plainText.Offset, plainText.Count);

                    VerifyExpectedCipherText(key, paddingMode, first, second);
                }

                return first;
            }
        }

        private static byte[] TransformFinalBlockParameterizedEncrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> plainText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            key.Mode = cipherMode;
            key.Padding = paddingMode;

            using (ICryptoTransform transform = key.CreateEncryptor(key.Key, iv))
            {
                byte[] first = transform.TransformFinalBlock(plainText.Array!, plainText.Offset, plainText.Count);

                if (transform.CanReuseTransform)
                {
                    byte[] second =
                        transform.TransformFinalBlock(plainText.Array, plainText.Offset, plainText.Count);

                    VerifyExpectedCipherText(key, paddingMode, first, second);
                }

                return first;
            }
        }

        private static byte[] CryptoStreamDecrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> cipherText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            key.IV = iv;
            key.Mode = cipherMode;
            key.Padding = paddingMode;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (ICryptoTransform transform = key.CreateDecryptor())
                using (CryptoStream cryptoStream = new(memoryStream, transform, CryptoStreamMode.Write, leaveOpen: true))
                {
                    cryptoStream.Write(cipherText);
                }

                return memoryStream.ToArray();
            }
        }

        private static byte[] CryptoStreamEncrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> plainText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            key.IV = iv;
            key.Mode = cipherMode;
            key.Padding = paddingMode;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (ICryptoTransform transform = key.CreateEncryptor())
                using (CryptoStream cryptoStream = new (memoryStream, transform, CryptoStreamMode.Write, leaveOpen: true))
                {
                    cryptoStream.Write(plainText);
                }

                return memoryStream.ToArray();
            }
        }

        private static byte[] OneShotArrayDecrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> cipherText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            switch (cipherMode)
            {
                case CipherMode.ECB:
                    return key.DecryptEcb(cipherText, paddingMode);
                case CipherMode.CBC:
                    return key.DecryptCbc(cipherText, iv, paddingMode);
                case CipherMode.CFB:
                    return key.DecryptCfb(cipherText, iv, paddingMode, key.FeedbackSize);
            }

            throw new ArgumentOutOfRangeException(
                nameof(cipherMode),
                cipherMode,
                "cipherMode is not handled");
        }

        private static byte[] OneShotArrayEncrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> plainText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            switch (cipherMode)
            {
                case CipherMode.ECB:
                    return key.EncryptEcb(plainText, paddingMode);
                case CipherMode.CBC:
                    return key.EncryptCbc(plainText, iv, paddingMode);
                case CipherMode.CFB:
                    return key.EncryptCfb(plainText, iv, paddingMode, key.FeedbackSize);
            }

            throw new ArgumentOutOfRangeException(
                nameof(cipherMode),
                cipherMode,
                "cipherMode is not handled");
        }

        private static byte[] OneShotSpanDecrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> cipherText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            int actualLen;
            byte[] decrypt = new byte[cipherText.Count + 3];
            Span<byte> destination = decrypt.AsSpan(1);

            switch (cipherMode)
            {
                case CipherMode.ECB:
                    actualLen = key.DecryptEcb(cipherText, destination, paddingMode);
                    break;
                case CipherMode.CBC:
                    actualLen = key.DecryptCbc(cipherText, iv, destination, paddingMode);
                    break;
                case CipherMode.CFB:
                    actualLen = key.DecryptCfb(cipherText, iv, destination, paddingMode, key.FeedbackSize);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(
                        nameof(cipherMode),
                        cipherMode,
                        "cipherMode is not handled");
            }

            Assert.Equal(0, decrypt[0]);
            return destination.Slice(0, actualLen).ToArray();
        }

        private static byte[] OneShotSpanEncrypt(
            SymmetricAlgorithm key,
            ArraySegment<byte> plainText,
            byte[] iv,
            CipherMode cipherMode,
            PaddingMode paddingMode)
        {
            int actualLen;
            byte[] encrypt = new byte[plainText.Count + (key.BlockSize / 8) + 3];
            Span<byte> destination = encrypt.AsSpan(1);

            switch (cipherMode)
            {
                case CipherMode.ECB:
                    actualLen = key.EncryptEcb(plainText, destination, paddingMode);
                    break;
                case CipherMode.CBC:
                    actualLen = key.EncryptCbc(plainText, iv, destination, paddingMode);
                    break;
                case CipherMode.CFB:
                    actualLen = key.EncryptCfb(plainText, iv, destination, paddingMode, key.FeedbackSize);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(
                        nameof(cipherMode),
                        cipherMode,
                        "cipherMode is not handled");
            }

            Assert.Equal(0, encrypt[0]);
            return destination.Slice(0, actualLen).ToArray();
        }

        private static void VerifyExpectedCipherText(
            SymmetricAlgorithm key,
            PaddingMode paddingMode,
            ReadOnlySpan<byte> expected,
            ReadOnlySpan<byte> actual)
        {
            if (paddingMode == PaddingMode.ANSIX923 || paddingMode == PaddingMode.ISO10126)
            {
                Index endIndex = new Index(key.BlockSize / 8, fromEnd: true);
                AssertExtensions.SequenceEqual(expected[0..endIndex], actual[0..endIndex]);
            }
            else
            {
                AssertExtensions.SequenceEqual(expected, actual);
            }
        }
    }
}
