// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;

namespace System.IO.Hashing
{
    public abstract partial class Crc32ParameterSet
    {
        private abstract class TableBasedCrc32 : Crc32ParameterSet
        {
            protected readonly uint[] _lookupTable;

            protected TableBasedCrc32(
                uint polynomial,
                uint initialValue,
                uint finalXorValue,
                bool reflectInput,
                bool reflectOutput)
                : base(polynomial, initialValue, finalXorValue, reflectInput, reflectOutput)
            {
                _lookupTable = GenerateLookupTable();
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
        }

        private sealed class ReflectedTableBasedCrc32 : TableBasedCrc32
        {
            internal ReflectedTableBasedCrc32(uint polynomial, uint initialValue, uint finalXorValue, bool reflectOutput)
                : base(polynomial, initialValue, finalXorValue, reflectInput: true, reflectOutput)
            {
            }

            internal override uint Update(uint value, ReadOnlySpan<byte> source)
            {
                uint[] lookupTable = _lookupTable;
                uint crc = value;

                Debug.Assert(lookupTable.Length == 256);

                foreach (byte dataByte in source)
                {
                    byte idx = (byte)(crc ^ dataByte);
                    crc = lookupTable[idx] ^ (crc >> 8);
                }

                return crc;
            }

            private protected override uint Compute(ReadOnlySpan<byte> source)
            {
                uint[] lookupTable = _lookupTable;
                uint crc = InitialValue;

                Debug.Assert(lookupTable.Length == 256);

                foreach (byte dataByte in source)
                {
                    byte idx = (byte)(crc ^ dataByte);
                    crc = lookupTable[idx] ^ (crc >> 8);
                }

                if (ReflectOutput != ReflectInput)
                {
                    crc = ReverseBits(crc);
                }

                return crc ^ FinalXorValue;
            }
        }

        private sealed class ForwardTableBasedCrc32 : TableBasedCrc32
        {
            internal ForwardTableBasedCrc32(uint polynomial, uint initialValue, uint finalXorValue, bool reflectOutput)
                : base(polynomial, initialValue, finalXorValue, reflectInput: false, reflectOutput)
            {
            }

            internal override uint Update(uint value, ReadOnlySpan<byte> source)
            {
                return UpdateScalar(value, source);
            }

            private uint UpdateScalar(uint value, ReadOnlySpan<byte> source)
            {
                uint[] lookupTable = _lookupTable;
                uint crc = value;

                Debug.Assert(lookupTable.Length == 256);

                foreach (byte dataByte in source)
                {
                    byte idx = (byte)((crc >> 24) ^ dataByte);
                    crc = lookupTable[idx] ^ (crc << 8);
                }

                return crc;
            }
        }
    }
}
