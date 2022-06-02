// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.ExtensionsTests
{
    public static class AuthorityKeyIdentifierTests
    {
        [Fact]
        public static void DefaultConstructor()
        {
            X509AuthorityKeyIdentifierExtension e = new X509AuthorityKeyIdentifierExtension();
            string oidValue = e.Oid.Value;
            Assert.Equal("2.5.29.35", oidValue);

            Assert.Empty(e.RawData);
            Assert.False(e.KeyIdentifier.HasValue, "e.KeyIdentifier.HasValue");
            Assert.Null(e.SimpleIssuer);
            Assert.False(e.RawIssuer.HasValue, "e.RawIssuer.HasValue");
            Assert.False(e.SerialNumber.HasValue, "e.SerialNumber.HasValue");
        }
    }
}
