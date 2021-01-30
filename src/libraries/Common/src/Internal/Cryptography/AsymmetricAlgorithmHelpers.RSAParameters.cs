// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class AsymmetricAlgorithmHelpers
    {
        internal static void FromRSAPublicKey(
            ReadOnlySpan<byte> source,
            ref RSAParameters rsaParameters)
        {
            Debug.Assert(rsaParameters.Modulus == null);
            Debug.Assert(rsaParameters.Exponent == null);
            Debug.Assert(rsaParameters.D == null);
            Debug.Assert(rsaParameters.P == null);
            Debug.Assert(rsaParameters.Q == null);
            Debug.Assert(rsaParameters.DP == null);
            Debug.Assert(rsaParameters.DQ == null);
            Debug.Assert(rsaParameters.InverseQ == null);

            try
            {
                // https://tools.ietf.org/html/rfc3447#appendix-A.1.1
                //
                // RSAPublicKey ::= SEQUENCE {
                //   modulus           INTEGER,  -- n
                //   publicExponent    INTEGER   -- e
                // }

                AsnValueReader reader = new AsnValueReader(source, AsnEncodingRules.DER);
                AsnValueReader pubKey = reader.ReadSequence();
                reader.ThrowIfNotEmpty();

                ReadOnlySpan<byte> modulus = pubKey.ReadIntegerBytes();
                ReadOnlySpan<byte> exponent = pubKey.ReadIntegerBytes();
                pubKey.ThrowIfNotEmpty();

                if (modulus[0] == 0)
                {
                    modulus = modulus.Slice(1);
                }

                if (exponent[0] == 0)
                {
                    exponent = exponent.Slice(1);
                }

                rsaParameters.Modulus = modulus.ToArray();
                rsaParameters.Exponent = exponent.ToArray();
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Arg_CryptographyException, e);
            }
        }

        internal static void FromRSAPrivateKey(
            ReadOnlySpan<byte> source,
            ref RSAParameters rsaParameters)
        {
            Debug.Assert(rsaParameters.Modulus == null);
            Debug.Assert(rsaParameters.Exponent == null);
            Debug.Assert(rsaParameters.D == null);
            Debug.Assert(rsaParameters.P == null);
            Debug.Assert(rsaParameters.Q == null);
            Debug.Assert(rsaParameters.DP == null);
            Debug.Assert(rsaParameters.DQ == null);
            Debug.Assert(rsaParameters.InverseQ == null);

            try
            {
                // https://tools.ietf.org/html/rfc3447#appendix-A.1.2
                //
                // RSAPrivateKey ::= SEQUENCE {
                //   version           Version,
                //   modulus           INTEGER,  -- n
                //   publicExponent    INTEGER,  -- e
                //   privateExponent   INTEGER,  -- d
                //   prime1            INTEGER,  -- p
                //   prime2            INTEGER,  -- q
                //   exponent1         INTEGER,  -- d mod (p-1)
                //   exponent2         INTEGER,  -- d mod (q-1)
                //   coefficient       INTEGER,  -- (inverse of q) mod p
                //   otherPrimeInfos   OtherPrimeInfos OPTIONAL
                // }

                AsnValueReader reader = new AsnValueReader(source, AsnEncodingRules.DER);
                AsnValueReader privKey = reader.ReadSequence();
                reader.ThrowIfNotEmpty();

                if (!privKey.TryReadInt32(out int version))
                {
                    throw new CryptographicException(SR.Arg_CryptographyException);
                }

                // version 0 is two-prime RSA.
                // version 1 is multi-prime RSA.
                // version 2+ is not defined (as of Jan 2021)
                if (version != 0)
                {
                    // This isn't expected, since multi-prime RSA isn't popular.
                    // If it starts getting hit then it would be worth a dedicated string,
                    // but until then just use the generic message.
                    throw new CryptographicException(SR.Arg_CryptographyException);
                }

                ReadOnlySpan<byte> modulus = privKey.ReadIntegerBytes();
                ReadOnlySpan<byte> exponent = privKey.ReadIntegerBytes();
                ReadOnlySpan<byte> d = privKey.ReadIntegerBytes();
                ReadOnlySpan<byte> p = privKey.ReadIntegerBytes();
                ReadOnlySpan<byte> q = privKey.ReadIntegerBytes();
                ReadOnlySpan<byte> dp = privKey.ReadIntegerBytes();
                ReadOnlySpan<byte> dq = privKey.ReadIntegerBytes();
                ReadOnlySpan<byte> qInv = privKey.ReadIntegerBytes();
                privKey.ThrowIfNotEmpty();

                rsaParameters.Modulus = ExportInteger(modulus);
                rsaParameters.Exponent = ExportInteger(exponent);

                int halfModulus = (rsaParameters.Modulus.Length + 1) / 2;

                rsaParameters.D = ExportInteger(d, rsaParameters.Modulus.Length);
                rsaParameters.P = ExportInteger(p, halfModulus);
                rsaParameters.Q = ExportInteger(q, halfModulus);
                rsaParameters.DP = ExportInteger(dp, halfModulus);
                rsaParameters.DQ = ExportInteger(dq, halfModulus);
                rsaParameters.InverseQ = ExportInteger(qInv, halfModulus);
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Arg_CryptographyException, e);
            }
        }

        private static byte[] ExportInteger(ReadOnlySpan<byte> integerValue, int targetSize = -1)
        {
            // The values are signed, so a leading 0 byte may be present to make the value positive.
            // Our export is unsigned, so strip it off if it's found.
            if (integerValue.Length > 1 && integerValue[0] == 0)
            {
                integerValue = integerValue.Slice(1);
            }

            if (targetSize > integerValue.Length)
            {
                byte[] ret = CryptoPool.AllocatePinnedArray(targetSize);
                int shift = targetSize - integerValue.Length;

                ret.AsSpan(0, shift).Clear();
                integerValue.CopyTo(ret.AsSpan(shift));
                return ret;
            }

            return integerValue.ToArray();
        }
    }
}
