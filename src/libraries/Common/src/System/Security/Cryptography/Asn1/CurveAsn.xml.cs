// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal ref partial struct CurveAsn
    {
        internal ReadOnlySpan<byte> A;
        internal ReadOnlySpan<byte> B;
        internal ReadOnlySpan<byte> Seed;
        internal bool SeedSet;
        internal readonly bool HasSeed => SeedSet || Seed.Length > 0;

        internal readonly void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal readonly void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            writer.WriteOctetString(A);
            writer.WriteOctetString(B);

            if (HasSeed)
            {
                writer.WriteBitString(Seed, 0);
            }

            writer.PopSequence(tag);
        }

        internal static CurveAsn Decode(ReadOnlySpan<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static CurveAsn Decode(Asn1Tag expectedTag, ReadOnlySpan<byte> encoded, AsnEncodingRules ruleSet)
        {
            try
            {
                AsnValueReader reader = new AsnValueReader(encoded, ruleSet);

                DecodeCore(ref reader, expectedTag, encoded, out CurveAsn decoded);
                reader.ThrowIfNotEmpty();
                return decoded;
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }

        internal static void Decode(scoped ref AsnValueReader reader, ReadOnlySpan<byte> rebind, out CurveAsn decoded)
        {
            Decode(ref reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(scoped ref AsnValueReader reader, Asn1Tag expectedTag, ReadOnlySpan<byte> rebind, out CurveAsn decoded)
        {
            try
            {
                DecodeCore(ref reader, expectedTag, rebind, out decoded);
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }

        private static void DecodeCore(scoped ref AsnValueReader reader, Asn1Tag expectedTag, ReadOnlySpan<byte> rebind, out CurveAsn decoded)
        {
            decoded = default;
            AsnValueReader sequenceReader = reader.ReadSequence(expectedTag);
            ReadOnlySpan<byte> rebindSpan = rebind;
            int offset;
            ReadOnlySpan<byte> tmpSpan;


            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            {
                decoded.A = rebindSpan.Overlaps(tmpSpan, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }
            else
            {
                decoded.A = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            {
                decoded.B = rebindSpan.Overlaps(tmpSpan, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }
            else
            {
                decoded.B = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveBitString))
            {

                if (sequenceReader.TryReadPrimitiveBitString(out _, out tmpSpan))
                {
                    decoded.Seed = rebindSpan.Overlaps(tmpSpan, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Seed = sequenceReader.ReadBitString(out _);
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
