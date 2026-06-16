// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.Tests
{
    public abstract class HpkeBaseTests
    {
        public abstract Hpke GenerateKey(HpkeSuite suite);
        public abstract Hpke ImportDecapsulationKey(HpkeSuite suite, ReadOnlySpan<byte> source);
        public abstract Hpke ImportEncapsulationKey(HpkeSuite suite, ReadOnlySpan<byte> source);

        [Theory]
        [MemberData(nameof(HpkeTestData.BaseVectors), MemberType = typeof(HpkeTestData))]
        public void BaseMode_DecryptVector(HpkeTestVector vector)
        {
            byte[] skRm = Convert.FromHexString(vector.RecipientPrivateKey);
            byte[] enc = Convert.FromHexString(vector.Enc);
            byte[] info = Convert.FromHexString(vector.Info);
            byte[] aad = Convert.FromHexString(vector.Aad0);
            byte[] plaintext = Convert.FromHexString(vector.Plaintext0);
            byte[] ciphertext = Convert.FromHexString(vector.Ciphertext0);

            using Hpke recipientKey = ImportDecapsulationKey(vector.Suite, skRm);
            using HpkeReceiver receiver = recipientKey.SetupReceiver(enc, info);

            byte[] decrypted = receiver.Open(ciphertext, aad);
            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(HpkeTestData.PskVectors), MemberType = typeof(HpkeTestData))]
        public void PskMode_DecryptVector(HpkeTestVector vector)
        {
            byte[] skRm = Convert.FromHexString(vector.RecipientPrivateKey);
            byte[] enc = Convert.FromHexString(vector.Enc);
            byte[] info = Convert.FromHexString(vector.Info);
            byte[] psk = Convert.FromHexString(vector.Psk!);
            byte[] pskId = Convert.FromHexString(vector.PskId!);
            byte[] aad0 = Convert.FromHexString(vector.Aad0);
            byte[] plaintext0 = Convert.FromHexString(vector.Plaintext0);
            byte[] ciphertext0 = Convert.FromHexString(vector.Ciphertext0);

            using Hpke recipientKey = ImportDecapsulationKey(vector.Suite, skRm);
            using HpkeReceiver receiver = recipientKey.SetupReceiverPsk(
                new ReadOnlySpan<byte>(enc), psk, pskId, info);

            byte[] decrypted0 = receiver.Open(ciphertext0, aad0);
            Assert.Equal(plaintext0, decrypted0);

            if (vector.Ciphertext1 is not null)
            {
                byte[] aad1 = Convert.FromHexString(vector.Aad1!);
                byte[] plaintext1 = Convert.FromHexString(vector.Plaintext1!);
                byte[] ciphertext1 = Convert.FromHexString(vector.Ciphertext1);

                byte[] decrypted1 = receiver.Open(ciphertext1, aad1);
                Assert.Equal(plaintext1, decrypted1);
            }

            if (vector.Ciphertext2 is not null)
            {
                byte[] aad2 = Convert.FromHexString(vector.Aad2!);
                byte[] ciphertext2 = Convert.FromHexString(vector.Ciphertext2);

                // Plaintext for seq 2 is the same as seq 0/1 in RFC 9180 test vectors
                byte[] decrypted2 = receiver.Open(ciphertext2, aad2);
                Assert.Equal(plaintext0, decrypted2);
            }
        }

        [Theory]
        [MemberData(nameof(HpkeTestData.AuthVectors), MemberType = typeof(HpkeTestData))]
        public void AuthMode_DecryptVector(HpkeTestVector vector)
        {
            byte[] skRm = Convert.FromHexString(vector.RecipientPrivateKey);
            byte[] pkSm = Convert.FromHexString(vector.SenderPublicKey!);
            byte[] enc = Convert.FromHexString(vector.Enc);
            byte[] info = Convert.FromHexString(vector.Info);
            byte[] aad = Convert.FromHexString(vector.Aad0);
            byte[] plaintext = Convert.FromHexString(vector.Plaintext0);
            byte[] ciphertext = Convert.FromHexString(vector.Ciphertext0);

            using Hpke recipientKey = ImportDecapsulationKey(vector.Suite, skRm);
            using Hpke senderPublicKey = ImportEncapsulationKey(vector.Suite, pkSm);
            using HpkeReceiver receiver = recipientKey.SetupReceiverAuth(enc, senderPublicKey, info);

            byte[] decrypted = receiver.Open(ciphertext, aad);
            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(HpkeTestData.AuthPskVectors), MemberType = typeof(HpkeTestData))]
        public void AuthPskMode_DecryptVector(HpkeTestVector vector)
        {
            byte[] skRm = Convert.FromHexString(vector.RecipientPrivateKey);
            byte[] pkSm = Convert.FromHexString(vector.SenderPublicKey!);
            byte[] enc = Convert.FromHexString(vector.Enc);
            byte[] info = Convert.FromHexString(vector.Info);
            byte[] psk = Convert.FromHexString(vector.Psk!);
            byte[] pskId = Convert.FromHexString(vector.PskId!);
            byte[] aad = Convert.FromHexString(vector.Aad0);
            byte[] plaintext = Convert.FromHexString(vector.Plaintext0);
            byte[] ciphertext = Convert.FromHexString(vector.Ciphertext0);

            using Hpke recipientKey = ImportDecapsulationKey(vector.Suite, skRm);
            using Hpke senderPublicKey = ImportEncapsulationKey(vector.Suite, pkSm);
            using HpkeReceiver receiver = recipientKey.SetupReceiverAuthPsk(
                enc, senderPublicKey, psk, pskId, info);

            byte[] decrypted = receiver.Open(ciphertext, aad);
            Assert.Equal(plaintext, decrypted);
        }
    }
}
