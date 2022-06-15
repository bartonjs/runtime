// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Test.Cryptography;
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

        [Fact]
        public static void RoundtripFull()
        {
            byte[] encoded = (
                "303C80140235857ED35BD13609F22DE8A71F93DFEBD3F495A11AA41830163114" +
                "301206035504030C0B49737375696E6743657274820852E6DEFA1D32A969").HexToByteArray();

            X509AuthorityKeyIdentifierExtension akid = new(encoded);
            Assert.True(akid.KeyIdentifier.HasValue, "akid.KeyIdentifier.HasValue");

            Assert.Equal(
                "0235857ED35BD13609F22DE8A71F93DFEBD3F495",
                akid.KeyIdentifier.Value.ByteArrayToHex());

            Assert.True(akid.RawIssuer.HasValue, "akid.RawIssuer.HasValue");
            Assert.NotNull(akid.SimpleIssuer);

            Assert.Equal(
                "A11AA41830163114301206035504030C0B49737375696E6743657274",
                akid.RawIssuer.Value.ByteArrayToHex());
            Assert.Equal(
                "30163114301206035504030C0B49737375696E6743657274",
                akid.SimpleIssuer.RawData.ByteArrayToHex());

            Assert.True(akid.SerialNumber.HasValue, "akid.SerialNumber.HasValue");
            Assert.Equal("52E6DEFA1D32A969", akid.SerialNumber.Value.ByteArrayToHex());

            X509AuthorityKeyIdentifierExtension akid2 = X509AuthorityKeyIdentifierExtension.Create(
                akid.KeyIdentifier.Value.Span,
                akid.SimpleIssuer,
                akid.SerialNumber.Value.Span);

            AssertExtensions.SequenceEqual(akid.RawData, akid2.RawData);
        }
    }
}
