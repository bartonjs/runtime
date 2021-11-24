// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Asymmetric
{
    public class AsymmetricTestKey<TAlg> where TAlg : AsymmetricAlgorithm
    {
        public ArraySegment<byte> Pkcs8PrivateKey { get; }
        public ArraySegment<byte> SubjectPublicKeyInfo { get; }
        public int KeySize { get; }

        public AsymmetricTestKey(int keySize, ArraySegment<byte> pkcs8, ArraySegment<byte> spki)
        {
            KeySize = keySize;
            Pkcs8PrivateKey = pkcs8;
            SubjectPublicKeyInfo = spki;
        }

        public bool HasPrivateKey => Pkcs8PrivateKey.Count > 0 || HasAlgorithmPrivateKey;
        protected virtual bool HasAlgorithmPrivateKey => false;

        public bool HasPublicKey => SubjectPublicKeyInfo.Count > 0 || HasAlgorithmPublicKey;
        protected virtual bool HasAlgorithmPublicKey => false;

        protected virtual IEnumerable<(string LoadMode, TAlg Key)> LoadAlgorithmPrivateKeys(Func<TAlg> factory)
        {
            yield break;
        }

        protected virtual IEnumerable<(string LoadMode, TAlg Key)> LoadAlgorithmPublicKeys(Func<TAlg> factory)
        {
            yield break;
        }

        public IEnumerable<(string LoadMode, TAlg Key)> LoadPrivateKeys(Func<TAlg> factory)
        {
            if (!HasPrivateKey)
            {
                throw new InvalidOperationException();
            }

            if (Pkcs8PrivateKey.Count > 0)
            {
                TAlg key = factory();
                key.ImportPkcs8PrivateKey(Pkcs8PrivateKey, out _);
                yield return ("PKCS8", key);
            }

            foreach (var tuple in LoadAlgorithmPrivateKeys(factory))
            {
                yield return tuple;
            }
        }

        public IEnumerable<(string LoadMode, TAlg Key)> LoadPublicKeys(Func<TAlg> factory)
        {
            if (!HasPublicKey)
            {
                throw new InvalidOperationException();
            }

            if (SubjectPublicKeyInfo.Count > 0)
            {
                TAlg key = factory();
                key.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo, out _);
                yield return ("SPKI", key);
            }

            foreach (var tuple in LoadAlgorithmPublicKeys(factory))
            {
                yield return tuple;
            }
        }
    }
}
