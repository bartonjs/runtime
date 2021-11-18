// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Symmetric
{
    public class SymmetricKnownValueTestCase
    {
        public byte[] Key { get; }
        public byte[] IV { get; }
        public ArraySegment<byte> Plaintext { get; }
        public ArraySegment<byte> Ciphertext { get; }
        public CipherMode CipherMode { get; }
        public PaddingMode PaddingMode { get; }
        public int? FeedbackSize { get; }

        public SymmetricKnownValueTestCase(
            byte[] key,
            byte[] iv,
            ArraySegment<byte> plaintext,
            ArraySegment<byte> ciphertext,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            int? feedbackSize)
        {
            Key = key;
            IV = iv;
            Plaintext = plaintext;
            Ciphertext = ciphertext;
            CipherMode = cipherMode;
            PaddingMode = paddingMode;
            FeedbackSize = feedbackSize;
        }

        public override string ToString()
        {
            if (CipherMode == CipherMode.CFB)
            {
                return $"key={Convert.ToHexString(Key)}, iv={Convert.ToHexString(IV)}, cm={CipherMode}{FeedbackSize}, pm={PaddingMode}, pt.Length={Plaintext.Count}";
            }

            if (CipherMode == CipherMode.ECB)
            {
                return $"key={Convert.ToHexString(Key)}, cm={CipherMode}, pm={PaddingMode}, pt.Length={Plaintext.Count}";
            }

            return $"key={Convert.ToHexString(Key)}, iv={Convert.ToHexString(IV)}, cm={CipherMode}, pm={PaddingMode}, pt.Length={Plaintext.Count}";
        }
    }
}
