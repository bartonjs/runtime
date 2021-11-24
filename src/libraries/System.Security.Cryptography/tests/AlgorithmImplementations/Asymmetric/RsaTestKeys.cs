// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography.Rsa.Tests;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Asymmetric
{
    internal static class RsaTestKeys
    {
        private static RsaTestKey? s_rsa1032;
        internal static RsaTestKey RSA1032 => s_rsa1032 ??= RsaTestKey.FromParameters(TestData.RSA1032Parameters);
    }
}
