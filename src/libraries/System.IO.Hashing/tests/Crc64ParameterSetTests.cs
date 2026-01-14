// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.IO.Hashing.Tests
{
    public static class Crc64ParameterSetTests
    {
        [Theory]
        [InlineData(0x42F0E1EBA9EA3693ul, 0x0000000000000000ul, false, false, 0x0000000000000000ul, 0x6C40DF5F0B497347ul, 0x0000000000000000ul, "CRC-64/ECMA-182")]
        [InlineData(0x000000000000001Bul, 0xFFFFFFFFFFFFFFFFul, true, true, 0xFFFFFFFFFFFFFFFFul, 0xB90956C775A41001ul, 0x5300000000000000ul, "CRC-64/GO-ISO")]
        [InlineData(0x259C84CBA6426349ul, 0xFFFFFFFFFFFFFFFFul, true, true, 0x0000000000000000ul, 0x75D4B74F024ECEEAul, 0x0000000000000000ul, "CRC-64/MS")]
        [InlineData(0xAD93D23594C93659ul, 0xFFFFFFFFFFFFFFFFul, true, true, 0xFFFFFFFFFFFFFFFFul, 0xAE8B14860A799888ul, 0xF310303B2B6F6E42uL, "CRC-64/NVME")]
        [InlineData(0xAD93D23594C935A9ul, 0x0000000000000000ul, true, true, 0x0000000000000000ul, 0xE9C6D914C4B8D9CAul, 0x0000000000000000ul, "CRC-64/REDIS")]
        [InlineData(0x42F0E1EBA9EA3693ul, 0xFFFFFFFFFFFFFFFFul, false, false, 0xFFFFFFFFFFFFFFFFul, 0x62EC59E3F1A4F00Aul, 0xFCACBEBD5931A992ul, "CRC-64/WE")]
        [InlineData(0x42F0E1EBA9EA3693ul, 0xFFFFFFFFFFFFFFFFul, true, true, 0xFFFFFFFFFFFFFFFFul, 0x995DC9BBDF1939FAul, 0x49958C9ABD7D353Ful, "CRC-64/XZ")]
        public static void KnownAnswers(
            ulong poly,
            ulong init,
            bool refIn,
            bool refOut,
            ulong xorOut,
            ulong check,
            ulong residue,
            string displayName)
        {
            _ = displayName;
            Crc64ParameterSet crc64 = Crc64ParameterSet.Create(poly, init, xorOut, refIn, refOut);
            Assert.Equal(poly, crc64.Polynomial);
            Assert.Equal(init, crc64.InitialValue);
            Assert.Equal(refIn, crc64.ReflectInput);
            Assert.Equal(refOut, crc64.ReflectOutput);
            Assert.Equal(xorOut, crc64.FinalXorValue);

            ulong crc = crc64.Compute("123456789"u8);
            Assert.Equal(check, crc);

            // https://reveng.sourceforge.io/crc-catalogue/17plus.htm uses the residue value as
            // the value in the register between a final reflection (if applicable) and the final XOR.
            // Since our version of residue includes the final XOR, we need to merge that in here
            // before checking the expected result.
            residue ^= xorOut;
            Assert.Equal(residue, crc64.Residue);
        }

        [Fact]
        public static void Ecma182IsCrc64()
        {
            Span<byte> data = stackalloc byte[95];
            data.Fill((byte)DateTime.Now.Ticks);

            ulong fromSet = Crc64ParameterSet.Ecma182.Compute(data);
            ulong fromCrc64 = Crc64.HashToUInt64(data);

            Assert.Equal(fromCrc64, fromSet);
            byte[] bytesFromSet = new byte[8];
            byte[] bytesFromCrc64 = new byte[8];

            Crc64.Hash(data, bytesFromCrc64);
            Crc64ParameterSet.Ecma182.ComputeBytes(data, bytesFromSet);

            AssertExtensions.SequenceEqual(bytesFromCrc64, bytesFromSet);
        }

        [Fact]
        public static void Ecma182FromParametersIsMatch()
        {
            Crc64ParameterSet preDefined = Crc64ParameterSet.Ecma182;
            Crc64ParameterSet fromParameters = Crc64ParameterSet.Create(
                polynomial: 0x42F0E1EBA9EA3693,
                initialValue: 0x0000000000000000,
                finalXorValue: 0x0000000000000000,
                reflectInput: false,
                reflectOutput: false);

            Assert.Equal(fromParameters.Polynomial, preDefined.Polynomial);
            Assert.Equal(fromParameters.InitialValue, preDefined.InitialValue);
            Assert.Equal(fromParameters.ReflectInput, preDefined.ReflectInput);
            Assert.Equal(fromParameters.ReflectOutput, preDefined.ReflectOutput);
            Assert.Equal(fromParameters.FinalXorValue, preDefined.FinalXorValue);
            Assert.Equal(fromParameters.BigEndianOutput, preDefined.BigEndianOutput);
            Assert.Equal(fromParameters.Residue, preDefined.Residue);

            Span<byte> data = stackalloc byte[95];
            data.Fill((byte)DateTime.Now.Ticks);

            ulong fromCreate = fromParameters.Compute(data);
            ulong fromPreDef = preDefined.Compute(data);

            Assert.Equal(fromCreate, fromPreDef);
            byte[] bytesFromCreate = new byte[8];
            byte[] bytesFromPreDef = new byte[8];

            fromParameters.ComputeBytes(data, bytesFromCreate);
            preDefined.ComputeBytes(data, bytesFromPreDef);

            AssertExtensions.SequenceEqual(bytesFromCreate, bytesFromPreDef);
        }
    }
}
