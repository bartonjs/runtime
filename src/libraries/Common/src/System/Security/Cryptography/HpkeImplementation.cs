// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    internal static partial class HpkeImplementation
    {
        internal static partial bool SupportsAny();

        internal static partial HPKE GenerateKeyCore(HpkeSuite suite);
        internal static partial HPKE ImportEncapsulationKeyCore(HpkeSuite suite, ReadOnlySpan<byte> source);
        internal static partial HPKE ImportDecapsulationKeyCore(HpkeSuite suite, ReadOnlySpan<byte> source);
    }
}
