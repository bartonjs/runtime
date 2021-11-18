// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;
using Xunit.Sdk;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Symmetric
{
    public abstract partial class SymmetricAlgorithmTestDriver<TCapabilities>
        where TCapabilities : ISymmetricAlgorithmCapabilities<TCapabilities>
    {
        [ConditionalFact(nameof(MissingOneShots))]
        public void OneShotsThrow()
        {
            using (SymmetricAlgorithm key = Create())
            {
                byte[] iv = key.IV;
                ArraySegment<byte> plaintext = ArraySegment<byte>.Empty;
                byte[] destination = iv;
                byte[] ciphertext = iv;

                Assert.Throws<NotSupportedException>(() => key.EncryptEcb(plaintext, PaddingMode.PKCS7));
                Assert.Throws<NotSupportedException>(() => key.EncryptCbc(plaintext, iv));
                Assert.Throws<NotSupportedException>(() => key.EncryptCfb(plaintext, iv));

                Assert.Throws<NotSupportedException>(() => key.EncryptEcb(plaintext, destination, PaddingMode.PKCS7));
                Assert.Throws<NotSupportedException>(() => key.EncryptCbc(plaintext, iv, destination));
                Assert.Throws<NotSupportedException>(() => key.EncryptCfb(plaintext, iv, destination));

                Assert.Throws<NotSupportedException>(() => key.TryEncryptEcb(plaintext, destination, PaddingMode.PKCS7, out _));
                Assert.Throws<NotSupportedException>(() => key.TryEncryptCbc(plaintext, iv, destination, out _));
                Assert.Throws<NotSupportedException>(() => key.TryEncryptCfb(plaintext, iv, destination, out _));

                Assert.Throws<NotSupportedException>(() => key.DecryptEcb(ciphertext, PaddingMode.PKCS7));
                Assert.Throws<NotSupportedException>(() => key.DecryptCbc(ciphertext, iv));
                Assert.Throws<NotSupportedException>(() => key.DecryptCfb(ciphertext, iv));

                Assert.Throws<NotSupportedException>(() => key.DecryptEcb(ciphertext, destination, PaddingMode.PKCS7));
                Assert.Throws<NotSupportedException>(() => key.DecryptCbc(ciphertext, iv, destination));
                Assert.Throws<NotSupportedException>(() => key.DecryptCfb(ciphertext, iv, destination));

                Assert.Throws<NotSupportedException>(() => key.TryDecryptEcb(ciphertext, destination, PaddingMode.PKCS7, out _));
                Assert.Throws<NotSupportedException>(() => key.TryDecryptCbc(ciphertext, iv, destination, out _));
                Assert.Throws<NotSupportedException>(() => key.TryDecryptCfb(ciphertext, iv, destination, out _));
            }
        }

        [Theory, MemberData(nameof(TestModes))]
        public void RandomKeyRoundtrip(SymmetricTestModes testMode)
        {
            using (SymmetricAlgorithm key = Create())
            {
                PaddingMode defaultPadding = key.Padding;
                CipherMode defaultBlockMode = key.Mode;
                byte[] randomIv = key.IV;

                byte[] encrypted = Encrypt(key, s_input0, randomIv, defaultBlockMode, defaultPadding, testMode);
                Assert.NotEqual(s_input0, encrypted);

                // Verify that encrypting didn't corrupt the input.
                AssertExtensions.SequenceEqual(Input0Span, s_input0);

                byte[] decrypted = Decrypt(key, encrypted, randomIv, defaultBlockMode, defaultPadding, testMode);
                AssertExtensions.SequenceEqual(s_input0, decrypted);
            }
        }

        [Theory, MemberData(nameof(TestModes))]
        public void VerifyKnownInputs(SymmetricTestModes testMode)
        {
            using (SymmetricAlgorithm key = Create())
            {
                int i = 0;

                foreach (SymmetricKnownValueTestCase input in EnumerateKnownValues())
                {
                    key.Key = input.Key;

                    if (input.FeedbackSize.HasValue)
                    {
                        key.FeedbackSize = input.FeedbackSize.Value;
                    }

                    try
                    {
                        byte[] encrypted = Encrypt(
                            key,
                            input.Plaintext,
                            input.IV,
                            input.CipherMode,
                            input.PaddingMode,
                            testMode);

                        VerifyExpectedCipherText(key, input.PaddingMode, input.Ciphertext, encrypted);
                    }
                    catch (XunitException xe)
                    {
                        throw new XunitException(
                            $"Error in known input {i} ({input}): {xe.Message}");
                    }
                    catch (Exception e)
                    {
                        throw new XunitException(
                            $"Unhandled exception from known input {i} ({input}): {e})");
                    }

                    i++;
                }
            }
        }
    }
}
