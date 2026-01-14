// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.IO.Hashing
{
    public abstract partial class Crc64ParameterSet
    {
        public static Crc64ParameterSet Ecma182 =>
            field ??= new Ecma182ParameterSet();

        public static Crc64ParameterSet GoIso =>
            field ??= Create(0x000000000000001B, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, true, true);

        public static Crc64ParameterSet Ms =>
            field ??= Create(0x259C84CBA6426349, 0xFFFFFFFFFFFFFFFF, 0x0000000000000000, true, true);

        public static Crc64ParameterSet Nvme =>
            field ??= Create(0xAD93D23594C93659, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, true, true);

        public static Crc64ParameterSet Redis =>
            field ??= Create(0xAD93D23594C935A9, 0x0000000000000000, 0x0000000000000000, true, true);

        public static Crc64ParameterSet We =>
            field ??= Create(0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, false, false);

        public static Crc64ParameterSet Xz =>
            field ??= Create(0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, true, true);

        private sealed class Ecma182ParameterSet : Crc64ParameterSet
        {
            public Ecma182ParameterSet()
                : base(0x42F0E1EBA9EA3693, 0x0000000000000000, 0x0000000000000000, false, false)
            {
                BigEndianOutput = true;
                Residue = 0x0000000000000000;
            }

            public override ulong Compute(ReadOnlySpan<byte> data) => Crc64.HashToUInt64(data);
            public override ulong Update(ulong value, ReadOnlySpan<byte> data) => Crc64.Update(value, data);
        }
    }
}
