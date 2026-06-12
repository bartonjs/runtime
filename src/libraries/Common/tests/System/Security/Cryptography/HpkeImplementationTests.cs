// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.Tests
{
    [ConditionalClass(typeof(Hpke), nameof(Hpke.IsSupported))]
    public class HpkeImplementationTests : HpkeBaseTests
    {
        public override Hpke GenerateKey(HpkeSuite suite)
        {
            return Hpke.GenerateKey(suite);
        }

        public override Hpke ImportDecapsulationKey(HpkeSuite suite, ReadOnlySpan<byte> source)
        {
            return Hpke.ImportDecapsulationKey(suite, source);
        }

        public override Hpke ImportEncapsulationKey(HpkeSuite suite, ReadOnlySpan<byte> source)
        {
            return Hpke.ImportEncapsulationKey(suite, source);
        }
    }
}
