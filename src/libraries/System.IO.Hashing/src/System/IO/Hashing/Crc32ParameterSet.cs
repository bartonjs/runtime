// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;

namespace System.IO.Hashing
{
    [CLSCompliant(false)]
    public sealed partial class Crc32ParameterSet
    {
        private readonly uint[] _lookupTable;

        /// <summary>Gets the polynomial value used for the CRC calculation.</summary>
        /// <value>The polynomial value used for the CRC calculation.</value>
        public uint Polynomial { get; }

        /// <summary>Gets the initial value (seed) for the CRC calculation.</summary>
        /// <value>The initial value (seed) for the CRC calculation.</value>
        public uint InitialValue { get; }

        /// <summary>Gets the value to XOR with the final CRC result.</summary>
        /// <value>The value to XOR with the final CRC result.</value>
        /// <remarks>For reflected-output CRC values, the final XOR is done after the bit-reflection.</remarks>
        public uint FinalXorValue { get; }

        /// <summary>Gets a value indicating whether the input bytes are reflected (reversed bit order) before processing.</summary>
        /// <value><see langword="true"/> if the input bytes are reflected; otherwise, <see langword="false"/>.</value>
        public bool ReflectInput { get; }

        /// <summary>Gets a value indicating whether the output CRC is reflected (reversed bit order) before applying the final XOR.</summary>
        /// <value><see langword="true"/> if the output CRC is reflected; otherwise, <see langword="false"/>.</value>
        public bool ReflectOutput { get; }

        /// <summary>
        ///   Gets a value indicating whether the output CRC bytes use the big-endian byte order.
        /// </summary>
        /// <value><see langword="true"/> if the output CRC bytes use the big-endian byte order; otherwise, <see langword="false"/>.</value>
        /// <seealso cref="Residue"/>
        public bool BigEndianOutput { get; private set; }

        /// <summary>
        ///   Gets the residue value used for the CRC calculation.
        /// </summary>
        /// <value>The residue value used for the CRC calculation.</value>
        /// <remarks>
        ///   The Cyclic Redundancy Check (CRC) residue is the value obtained by
        ///   the computation <c>CRC(data concat CRC(data))</c>, which is the same value
        ///   for any data input.
        ///   The residue value differs across different parameter sets, and the residue is
        ///   only valid under either a big-endian or little-endian output encoding.
        /// </remarks>
        /// <seealso cref="BigEndianOutput"/>
        public uint Residue { get; private set; }

        private Crc32ParameterSet(uint polynomial, uint initialValue, uint finalXorValue, bool reflectInput, bool reflectOutput)
        {
            Polynomial = polynomial;
            InitialValue = initialValue;
            FinalXorValue = finalXorValue;
            ReflectInput = reflectInput;
            ReflectOutput = reflectOutput;

            _lookupTable = GenerateLookupTable();
        }

        /// <summary>Creates a new <see cref="Crc32ParameterSet"/> with the specified parameters.</summary>
        /// <param name="polynomial">The polynomial value used for the CRC calculation.</param>
        /// <param name="initialValue">The initial value (seed) for the CRC calculation.</param>
        /// <param name="finalXorValue">The value to XOR with the final CRC result.</param>
        /// <param name="reflectInput">Whether the input bytes are reflected (reversed bit order) before processing.</param>
        /// <param name="reflectOutput">Whether the output CRC is reflected (reversed bit order) before applying the final XOR.</param>
        /// <returns>A new <see cref="Crc32ParameterSet"/> instance.</returns>
        [CLSCompliant(false)]
        public static Crc32ParameterSet Create(
            uint polynomial,
            uint initialValue,
            uint finalXorValue,
            bool reflectInput,
            bool reflectOutput)
        {
            Crc32ParameterSet set = new Crc32ParameterSet(polynomial, initialValue, finalXorValue, reflectInput, reflectOutput);
            Span<byte> buf = stackalloc byte[12];

            static void Test(
                Crc32ParameterSet set,
                ReadOnlySpan<byte> data,
                Span<byte> buf,
                out uint bigEndian,
                out uint littleEndian)
            {
                data.CopyTo(buf);

                Span<byte> dest = buf.Slice(data.Length, sizeof(uint));
                ReadOnlySpan<byte> full = buf.Slice(0, data.Length + sizeof(uint));

                uint crc = set.Compute(data);
                BinaryPrimitives.WriteUInt32BigEndian(dest, crc);
                bigEndian = set.Compute(full);
                BinaryPrimitives.WriteUInt32LittleEndian(dest, crc);
                littleEndian = set.Compute(full);
            }

            Test(set, "12345678"u8, buf, out uint r1BE, out uint r1LE);
            Test(set, "SHORTER"u8, buf, out uint r2BE, out uint r2LE);

            // Determine which encoding produces a consistent residue
            if (r1LE == r2LE)
            {
                set.BigEndianOutput = false;
                set.Residue = r1LE;
            }
            else if (r1BE == r2BE)
            {
                set.BigEndianOutput = true;
                set.Residue = r1BE;
            }
            else
            {
                throw new ArgumentException("The provided CRC-32 parameters do not produce a consistent residue for either little-endian or big-endian output.");
            }

            return set;
        }

        public void ComputeBytes(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            uint crc = Compute(data);

            if (BigEndianOutput)
            {
                BinaryPrimitives.WriteUInt32BigEndian(destination, crc);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(destination, crc);
            }
        }

        public uint Update(uint value, ReadOnlySpan<byte> data)
        {
            uint[] lookupTable = _lookupTable;
            uint crc = value;

            foreach (byte dataByte in data)
            {
                if (ReflectInput)
                {
                    byte idx = (byte)(crc ^ dataByte);
                    crc = lookupTable[idx] ^ (crc >> 8);
                }
                else
                {
                    byte idx = (byte)((crc >> 24) ^ dataByte);
                    crc = lookupTable[idx] ^ (crc << 8);
                }
            }

            return crc;
        }

        public uint Finalize(uint value)
        {
            uint crc = value;

            if (ReflectOutput != ReflectInput)
            {
                crc = ReverseBits(crc);
            }

            return crc ^ FinalXorValue;
        }

        public uint Compute(ReadOnlySpan<byte> data)
        {
            uint[] lookupTable = _lookupTable;
            uint crc = InitialValue;

            for (int i = 0; i < data.Length; i++)
            {
                byte dataByte = data[i];

                if (ReflectInput)
                {
                    byte idx = (byte)(crc ^ dataByte);
                    crc = lookupTable[idx] ^ (crc >> 8);
                }
                else
                {
                    byte idx = (byte)((crc >> 24) ^ dataByte);
                    crc = lookupTable[idx] ^ (crc << 8);
                }
            }

            if (ReflectOutput != ReflectInput)
            {
                crc = ReverseBits(crc);
            }

            return crc ^ FinalXorValue;
        }

        private uint[] GenerateLookupTable()
        {
            uint[] table = new uint[256];

            if (!ReflectInput)
            {
                uint crc = 0x80000000u;

                for (int i = 1; i < 256; i <<= 1)
                {
                    if ((crc & 0x80000000u) != 0)
                    {
                        crc = (crc << 1) ^ Polynomial;
                    }
                    else
                    {
                        crc <<= 1;
                    }

                    for (int j = 0; j < i; j++)
                    {
                        table[i + j] = crc ^ table[j];
                    }
                }
            }
            else
            {

                for (int i = 1; i < 256; i++)
                {
                    uint r = ReverseBits((uint)i);

                    const uint LastBit = 0x80000000u;

                    for (int j = 0; j < 8; j++)
                    {
                        if ((r & LastBit) != 0)
                        {
                            r = (r << 1) ^ Polynomial;
                        }
                        else
                        {
                            r <<= 1;
                        }
                    }

                    table[i] = ReverseBits(r);
                }
            }

            return table;
        }

        private static uint ReverseBits(uint value)
        {
            value = ((value & 0xAAAAAAAA) >> 1) | ((value & 0x55555555) << 1);
            value = ((value & 0xCCCCCCCC) >> 2) | ((value & 0x33333333) << 2);
            value = ((value & 0xF0F0F0F0) >> 4) | ((value & 0x0F0F0F0F) << 4);
            value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
            return (value >> 16) | (value << 16);
        }
    }
}
