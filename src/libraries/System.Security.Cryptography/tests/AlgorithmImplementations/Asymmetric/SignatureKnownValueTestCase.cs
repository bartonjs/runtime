// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Test.Cryptography;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Asymmetric
{
    public class SignatureKnownValueTestCase<TAlg> where TAlg : AsymmetricAlgorithm
    {
        public AsymmetricTestKey<TAlg> Key { get; }
        public ArraySegment<byte> Data { get; }
        public byte[] Signature { get; }
        public HashAlgorithmName HashAlgorithm { get; }
        private byte[]? _hash;

        public SignatureKnownValueTestCase(
            AsymmetricTestKey<TAlg> key,
            ArraySegment<byte> data,
            byte[] signature,
            HashAlgorithmName hashAlgorithm)
        {
            Key = key;
            Data = data;
            Signature = signature;
            HashAlgorithm = hashAlgorithm;
        }

        public override string ToString()
        {
            return $"key={typeof(TAlg).Name}-{Key.KeySize}, data.Length={Data.Count}, hashAlg={HashAlgorithm.Name}";
        }

        public byte[] LazyGetHash()
        {
            if (_hash is null)
            {
                _hash = CryptoUtils.HashData(HashAlgorithm, Data);
            }

            return _hash;
        }

        public byte[]? LazyGetHash(SignatureTestDriver.VerifyMode verifyMode)
        {
            if (verifyMode == SignatureTestDriver.VerifyMode.VerifyHashArray ||
                verifyMode == SignatureTestDriver.VerifyMode.VerifyHashSpan)
            {
                return LazyGetHash();
            }

            return null;
        }
    }
}
