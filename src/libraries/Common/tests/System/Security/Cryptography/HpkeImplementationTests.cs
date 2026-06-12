// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.Tests
{
    [ConditionalClass(typeof(HPKE), nameof(HPKE.IsSupported))]
    public class HpkeImplementationTests : HpkeBaseTests
    {
        public override HPKE GenerateKey(HpkeSuite suite)
        {
            return HPKE.GenerateKey(suite);
        }

        public override HPKE ImportDecapsulationKey(HpkeSuite suite, ReadOnlySpan<byte> source)
        {
            return HPKE.ImportDecapsulationKey(suite, source);
        }

        public override HPKE ImportEncapsulationKey(HpkeSuite suite, ReadOnlySpan<byte> source)
        {
            return HPKE.ImportEncapsulationKey(suite, source);
        }
    }
}
