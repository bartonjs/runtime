// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.IO.Hashing.Tests
{
    public static class Crc32ParameterSetTests
    {
        [Theory]
        [InlineData(0x814141ab, 0x00000000, false, false, 0x00000000, 0x3010bf7f, 0x00000000, "CRC-32/AIXM")]
        [InlineData(0xf4acfb13, 0xffffffff, true, true, 0xffffffff, 0x1697d06a, 0x904cddbf, "CRC-32/AUTOSAR")]
        [InlineData(0xa833982b, 0xffffffff, true, true, 0xffffffff, 0x87315576, 0x45270551, "CRC-32/BASE91-D")]
        [InlineData(0x04c11db7, 0xffffffff, false, false, 0xffffffff, 0xfc891918, 0xc704dd7b, "CRC-32/BZIP2")]
        [InlineData(0x8001801b, 0x00000000, true, true, 0x00000000, 0x6ec2edc4, 0x00000000, "CRC-32/CD-ROM-EDC")]
        [InlineData(0x04c11db7, 0x00000000, false, false, 0xffffffff, 0x765e7680, 0xc704dd7b, "CRC-32/CKSUM")]
        [InlineData(0x1edc6f41, 0xffffffff, true, true, 0xffffffff, 0xe3069283, 0xb798b438, "CRC-32/ISCSI")]
        [InlineData(0x04c11db7, 0xffffffff, true, true, 0xffffffff, 0xcbf43926, 0xdebb20e3, "CRC-32/ISO-HDLC")]
        [InlineData(0x04c11db7, 0xffffffff, true, true, 0x00000000, 0x340bc6d9, 0x00000000, "CRC-32/JAMCRC")]
        [InlineData(0x741b8cd7, 0xffffffff, true, true, 0x00000000, 0xd2c22f51, 0x00000000, "CRC-32/MEF")]
        [InlineData(0x04c11db7, 0xffffffff, false, false, 0x00000000, 0x0376e6e7, 0x00000000, "CRC-32/MPEG-2")]
        [InlineData(0x000000af, 0x00000000, false, false, 0x00000000, 0xbd0be338, 0x00000000, "CRC-32/XFER")]
        public static void KnownAnswers(
            uint poly,
            uint init,
            bool refIn,
            bool refOut,
            uint xorOut,
            uint check,
            uint residue,
            string displayName)
        {
            _ = displayName;
            Crc32ParameterSet crc32 = Crc32ParameterSet.Create(poly, init, xorOut, refIn, refOut);
            Assert.Equal(poly, crc32.Polynomial);
            Assert.Equal(init, crc32.InitialValue);
            Assert.Equal(refIn, crc32.ReflectInput);
            Assert.Equal(refOut, crc32.ReflectOutput);
            Assert.Equal(xorOut, crc32.FinalXorValue);

            // https://reveng.sourceforge.io/crc-catalogue/17plus.htm uses the residue value as
            // the value in the register between a final reflection (if applicable) and the final XOR.
            // Since our version of residue includes the final XOR, we need to merge that in here
            // before checking the expected result.
            residue ^= xorOut;
            Assert.Equal(residue, crc32.Residue);

            uint crc = crc32.Compute("123456789"u8);
            Assert.Equal(check, crc);
        }

        [Fact]
        public static void IsoHdlcIsCrc32()
        {
            Span<byte> data = stackalloc byte[95];
            data.Fill((byte)DateTime.Now.Ticks);

            uint fromSet = Crc32ParameterSet.IsoHdlc.Compute(data);
            uint fromCrc32 = Crc32.HashToUInt32(data);

            Assert.Equal(fromCrc32, fromSet);
            byte[] bytesFromSet = new byte[4];
            byte[] bytesFromCrc32 = new byte[4];

            Crc32.Hash(data, bytesFromCrc32);
            Crc32ParameterSet.IsoHdlc.ComputeBytes(data, bytesFromSet);

            AssertExtensions.SequenceEqual(bytesFromCrc32, bytesFromSet);
        }

        [Fact]
        public static void IsoHdlcFromParametersIsMatch()
        {
            Crc32ParameterSet preDefined = Crc32ParameterSet.IsoHdlc;
            Crc32ParameterSet fromParameters = Crc32ParameterSet.Create(
                polynomial: 0x04C11DB7,
                initialValue: 0xFFFFFFFF,
                finalXorValue: 0xFFFFFFFF,
                reflectInput: true,
                reflectOutput: true);

            Assert.Equal(fromParameters.Polynomial, preDefined.Polynomial);
            Assert.Equal(fromParameters.InitialValue, preDefined.InitialValue);
            Assert.Equal(fromParameters.ReflectInput, preDefined.ReflectInput);
            Assert.Equal(fromParameters.ReflectOutput, preDefined.ReflectOutput);
            Assert.Equal(fromParameters.FinalXorValue, preDefined.FinalXorValue);
            Assert.Equal(fromParameters.BigEndianOutput, preDefined.BigEndianOutput);
            Assert.Equal(fromParameters.Residue, preDefined.Residue);

            Span<byte> data = stackalloc byte[95];
            data.Fill((byte)DateTime.Now.Ticks);

            uint fromCreate = fromParameters.Compute(data);
            uint fromPreDef = preDefined.Compute(data);

            Assert.Equal(fromCreate, fromPreDef);
            byte[] bytesFromCreate = new byte[4];
            byte[] bytesFromPreDef = new byte[4];

            fromParameters.ComputeBytes(data, bytesFromCreate);
            preDefined.ComputeBytes(data, bytesFromPreDef);

            AssertExtensions.SequenceEqual(bytesFromCreate, bytesFromPreDef);
        }
    }
}
