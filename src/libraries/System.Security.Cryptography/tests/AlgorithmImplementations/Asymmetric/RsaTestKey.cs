// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Formats.Asn1;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Asymmetric
{
    public class RsaTestKey : AsymmetricTestKey<RSA>
    {
        public ArraySegment<byte> RsaPrivateKey { get; }
        public ArraySegment<byte> RsaPublicKey { get; }
        public RSAParameters RsaParameters { get; }

        protected override bool HasAlgorithmPrivateKey => RsaPrivateKey.Count > 0 || RsaParameters.D != null;
        protected override bool HasAlgorithmPublicKey => RsaPublicKey.Count > 0 || RsaParameters.Modulus != null;

        private RsaTestKey(
            int keySize,
            ArraySegment<byte> pkcs8,
            ArraySegment<byte> spki,
            ArraySegment<byte> rsaPrivateKey,
            ArraySegment<byte> rsaPublicKey,
            in RSAParameters rsaParameters)
            : base(keySize, pkcs8, spki)
        {
            RsaPrivateKey = rsaPrivateKey;
            RsaPublicKey = rsaPublicKey;
            RsaParameters = rsaParameters;
        }

        protected override IEnumerable<(string LoadMode, RSA Key)> LoadAlgorithmPrivateKeys(Func<RSA> factory)
        {
            if (RsaPrivateKey.Count > 0)
            {
                RSA key = factory();
                key.ImportRSAPrivateKey(RsaPrivateKey, out _);
                yield return ("RSAPrivateKey", key);
            }

            if (RsaParameters.D != null)
            {
                RSA key = factory();
                key.ImportParameters(RsaParameters);
                yield return ("RSAParameters", key);
            }
        }

        protected override IEnumerable<(string LoadMode, RSA Key)> LoadAlgorithmPublicKeys(Func<RSA> factory)
        {
            if (RsaPublicKey.Count > 0)
            {
                RSA key = factory();
                key.ImportRSAPublicKey(RsaPublicKey, out _);
                yield return ("RSAPublicKey", key);
            }

            if (RsaParameters.Modulus != null)
            {
                RSA key = factory();

                key.ImportParameters(
                    new RSAParameters
                    {
                        Modulus = RsaParameters.Modulus,
                        Exponent = RsaParameters.Exponent,
                    });

                yield return ("RSAParameters", key);
            }
        }

        public static RsaTestKey FromParameters(RSAParameters rsaParameters)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                writer.WriteIntegerUnsigned(rsaParameters.Modulus);
                writer.WriteIntegerUnsigned(rsaParameters.Exponent);
            }

            byte[] rsaPublic = writer.Encode();
            writer.Reset();

            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.840.113549.1.1.1");
                    writer.WriteNull();
                }

                writer.WriteBitString(rsaPublic);
            }

            byte[] spki = writer.Encode();
            writer.Reset();

            byte[]? rsaPrivate = null;
            byte[]? pkcs8 = null;

            if (rsaParameters.D is not null)
            {
                using (writer.PushSequence())
                {
                    writer.WriteInteger(0);
                    writer.WriteIntegerUnsigned(rsaParameters.Modulus);
                    writer.WriteIntegerUnsigned(rsaParameters.Exponent);
                    WriteKeyInteger(writer, rsaParameters.D);
                    WriteKeyInteger(writer, rsaParameters.P);
                    WriteKeyInteger(writer, rsaParameters.Q);
                    WriteKeyInteger(writer, rsaParameters.DP);
                    WriteKeyInteger(writer, rsaParameters.DQ);
                    WriteKeyInteger(writer, rsaParameters.InverseQ);
                }

                rsaPrivate = writer.Encode();
                writer.Reset();

                using (writer.PushSequence())
                {
                    writer.WriteInteger(0);

                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("1.2.840.113549.1.1.1");
                        writer.WriteNull();
                    }

                    writer.WriteOctetString(rsaPrivate);
                }

                pkcs8 = writer.Encode();
            }

            return new RsaTestKey(
                rsaParameters.Modulus.Length * 8,
                pkcs8,
                spki,
                rsaPrivate,
                rsaPublic,
                rsaParameters);
        }

        private static void WriteKeyInteger(AsnWriter writer, ReadOnlySpan<byte> value)
        {
            int start = 0;

            while (start < value.Length && value[0] == 0)
            {
                start++;
            }

            writer.WriteIntegerUnsigned(value.Slice(start));
        }
    }
}
