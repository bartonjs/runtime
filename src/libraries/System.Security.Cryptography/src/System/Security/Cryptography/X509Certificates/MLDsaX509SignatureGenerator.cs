// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Formats.Asn1;
using Internal.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed class MLDsaX509SignatureGenerator : X509SignatureGenerator
    {
        private readonly MLDsa _key;

        internal MLDsaX509SignatureGenerator(MLDsa key)
        {
            Debug.Assert(key != null);

            _key = key;
        }

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
        {
            if (!string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(hashAlgorithm),
                    hashAlgorithm,
                    SR.Format(SR.Cryptography_CertReq_PureSignForbidsHashAlgorithmName, "ML-DSA"));
            }

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteObjectIdentifier(_key.Algorithm.Oid);
            writer.PopSequence();
            return writer.Encode();
        }

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            ArgumentNullException.ThrowIfNull(data);

            if (!string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(hashAlgorithm),
                    hashAlgorithm,
                    SR.Format(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithm.Name));
            }

            byte[] signature = new byte[_key.Algorithm.SignatureSizeInBytes];
            int written = _key.SignData(data, signature);
            Debug.Assert(written == signature.Length);
            return signature;
        }

        protected override PublicKey BuildPublicKey()
        {
            Oid oid = new Oid(_key.Algorithm.Oid, null);
            byte[] pkBytes = new byte[_key.Algorithm.PublicKeySizeInBytes];
            int written = _key.ExportMLDsaPublicKey(pkBytes);
            Debug.Assert(written == pkBytes.Length);

            return new PublicKey(
                oid,
                null,
                new AsnEncodedData(oid, pkBytes, skipCopy: true));
        }
    }
}
