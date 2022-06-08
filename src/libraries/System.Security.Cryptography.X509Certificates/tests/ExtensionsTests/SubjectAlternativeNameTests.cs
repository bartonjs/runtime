// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net;
using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.ExtensionsTests
{
    public static class SubjectAlternativeNameTests
    {
        [Fact]
        public static void DefaultConstructor()
        {
            // TODO: Write behavior tests.
        }

        [Fact]
        public static void EnumerateDnsNames()
        {
            SubjectAlternativeNameBuilder builder = new SubjectAlternativeNameBuilder();
            builder.AddDnsName("foo");
            builder.AddIpAddress(IPAddress.Loopback);
            builder.AddUserPrincipalName("user@some.domain");
            builder.AddIpAddress(IPAddress.IPv6Loopback);
            builder.AddDnsName("*.foo");
            X509Extension built = builder.Build(true);

            X509SubjectAlternativeNameExtension ext = new();
            ext.CopyFrom(built);

            Assert.Equal(new[] { "foo", "*.foo" }, ext.EnumerateDnsNames());
        }

        [Fact]
        public static void EnumerateIPAddresses()
        {
            SubjectAlternativeNameBuilder builder = new SubjectAlternativeNameBuilder();
            builder.AddDnsName("foo");
            builder.AddIpAddress(IPAddress.Loopback);
            builder.AddUserPrincipalName("user@some.domain");
            builder.AddIpAddress(IPAddress.IPv6Loopback);
            builder.AddDnsName("*.foo");
            X509Extension built = builder.Build(true);

            X509SubjectAlternativeNameExtension ext = new();
            ext.CopyFrom(built);

            Assert.Equal(new[] { IPAddress.Loopback, IPAddress.IPv6Loopback }, ext.EnumerateIPAddresses());
        }
    }
}
