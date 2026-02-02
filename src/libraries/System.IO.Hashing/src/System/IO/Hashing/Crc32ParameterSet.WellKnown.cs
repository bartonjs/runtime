// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;

namespace System.IO.Hashing
{
    public abstract partial class Crc32ParameterSet
    {
        /// <summary>
        ///   Gets the parameter set for the variant of CRC-32 as used in
        ///   ITU-T V.42 and IEEE 802.3.
        /// </summary>
        /// <value>
        ///   The parameter set for the variant of CRC-32 as used in
        ///   ITU-T V.42 and IEEE 802.3.
        /// </value>
        public static Crc32ParameterSet Crc32 =>
            field ??= new Ieee8023ParameterSet();

        /// <summary>
        ///   Gets the parameter set for the CRC-32C variant of CRC-32.
        /// </summary>
        /// <value>
        ///   The parameter set for the CRC-32C variant of CRC-32.
        /// </value>
        public static Crc32ParameterSet Crc32C =>
            field ??= MakeCrc32CParameterSet();

        private static Crc32ParameterSet MakeCrc32CParameterSet()
        {
#if NET
            if (System.Runtime.Intrinsics.X86.Sse.IsSupported || System.Runtime.Intrinsics.Arm.Crc32.IsSupported)
            {
                return new Crc32CParameterSet();
            }
#endif

            return Create(
                polynomial: 0x1edc6f41,
                initialValue: 0xffffffff,
                finalXorValue: 0xffffffff,
                reflectInput: true,
                reflectOutput: true);
        }

        private sealed class Ieee8023ParameterSet : Crc32ParameterSet
        {
            public Ieee8023ParameterSet()
                : base(0x04c11db7, 0xffffffff, 0xffffffff, true, true)
            {
            }

            private protected override uint Compute(ReadOnlySpan<byte> source) => Hashing.Crc32.HashToUInt32(source);
            internal override uint Update(uint value, ReadOnlySpan<byte> source) => Hashing.Crc32.Update(value, source);
        }

#if NET
        private sealed class Crc32CParameterSet : Crc32ParameterSet
        {
            public Crc32CParameterSet()
                : base(0x1edc6f41, 0xffffffff, 0xffffffff, true, true)
            {
            }

            private protected override uint Compute(ReadOnlySpan<byte> data)
            {
                if (data.Length == 0)
                {
                    return 0;
                }

                uint crc = UpdateIntrinsic(InitialValue, data);
                return crc ^ FinalXorValue;
            }

            internal override uint Update(uint value, ReadOnlySpan<byte> source) => UpdateIntrinsic(value, source);

            private static uint UpdateIntrinsic(uint crc, ReadOnlySpan<byte> source)
            {
                if (System.Runtime.Intrinsics.X86.Sse42.IsSupported)
                {
                    ReadOnlySpan<uint> uintData = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, uint>(source);

                    foreach (uint value in uintData)
                    {
                        crc = System.Runtime.Intrinsics.X86.Sse42.Crc32(crc, value);
                    }

                    // SSE 4.2 defines a ushort version as well, but that will only save us one byte,
                    // so not worth the branch and cast.

                    ReadOnlySpan<byte> remainingBytes = source.Slice(uintData.Length * sizeof(uint));

                    foreach (byte value in remainingBytes)
                    {
                        crc = System.Runtime.Intrinsics.X86.Sse42.Crc32(crc, value);
                    }
                }
                else
                {
                    Debug.Assert(System.Runtime.Intrinsics.Arm.Crc32.IsSupported);

                    if (System.Runtime.Intrinsics.Arm.Crc32.Arm64.IsSupported)
                    {
                        ReadOnlySpan<ulong> ulongData = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, ulong>(source);

                        foreach (ulong value in ulongData)
                        {
                            crc = System.Runtime.Intrinsics.Arm.Crc32.Arm64.ComputeCrc32C(crc, value);
                        }

                        source = source.Slice(ulongData.Length * sizeof(ulong));
                    }

                    ReadOnlySpan<uint> uintData = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, uint>(source);

                    foreach (uint value in uintData)
                    {
                        crc = System.Runtime.Intrinsics.Arm.Crc32.Arm64.ComputeCrc32C(crc, value);
                    }

                    ReadOnlySpan<byte> remainingBytes = source.Slice(uintData.Length * sizeof(uint));

                    foreach (byte value in remainingBytes)
                    {
                        crc = System.Runtime.Intrinsics.Arm.Crc32.Arm64.ComputeCrc32C(crc, value);
                    }
                }

                return crc;
            }
        }
#endif
    }
}
