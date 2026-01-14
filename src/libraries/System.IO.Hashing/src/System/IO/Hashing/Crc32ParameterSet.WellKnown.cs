// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.IO.Hashing
{
    public abstract partial class Crc32ParameterSet
    {
        public static Crc32ParameterSet Aixm =>
            field ??= Create(0x814141ab, 0x00000000, 0x00000000, false, false);

        public static Crc32ParameterSet Autosar =>
            field ??= Create(0xf4acfb13, 0xffffffff, 0xffffffff, true, true);

        public static Crc32ParameterSet Base91D =>
            field ??= Create(0xa833982b, 0xffffffff, 0xffffffff, true, true);

        public static Crc32ParameterSet Bzip2 =>
            field ??= Create(0x04c11db7, 0xffffffff, 0xffffffff, false, false);

        public static Crc32ParameterSet CdRomEdc =>
            field ??= Create(0x8001801b, 0x00000000, 0x00000000, true, true);

        public static Crc32ParameterSet Cksum =>
            field ??= Create(0x04c11db7, 0x00000000, 0xffffffff, false, false);

        public static Crc32ParameterSet IscsiCrc =>
            field ??= Create(0x1edc6f41, 0xffffffff, 0xffffffff, true, true);

        public static Crc32ParameterSet IsoHdlc =>
            field ??= new IsoHdlcParameterSet();

        public static Crc32ParameterSet Jamcrc =>
            field ??= Create(0x04c11db7, 0xffffffff, 0x00000000, true, true);

        public static Crc32ParameterSet Mef =>
            field ??= Create(0x741b8cd7, 0xffffffff, 0x00000000, true, true);

        public static Crc32ParameterSet Mpeg2 =>
            field ??= Create(0x04c11db7, 0xffffffff, 0x00000000, false, false);

        public static Crc32ParameterSet Xfer =>
            field ??= Create(0x000000af, 0x00000000, 0x00000000, false, false);

        private sealed class IsoHdlcParameterSet : Crc32ParameterSet
        {
            public IsoHdlcParameterSet()
                : base(0x04c11db7, 0xffffffff, 0xffffffff, true, true)
            {
                BigEndianOutput = false;
                Residue = 0xdebb20e3 ^ 0xffffffff;
            }

            public override uint Compute(ReadOnlySpan<byte> data) => Crc32.HashToUInt32(data);
            public override uint Update(uint value, ReadOnlySpan<byte> data) => Crc32.Update(value, data);
        }
    }
}
