// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net;
using System.Security.Cryptography.X509Certificates;
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

        [Fact]
        public static void MatchesIpAddress()
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

            Assert.False(ext.MatchesHostname(IPAddress.Broadcast.ToString()), "Matches IPAddress.Broadcast");
            Assert.False(ext.MatchesHostname(IPAddress.IPv6Any.ToString()), "Matches IPAddress.IPv6Any");
            Assert.False(ext.MatchesHostname(IPAddress.Any.ToString()), "Matches IPAddress.Any");
            Assert.False(ext.MatchesHostname(IPAddress.None.ToString()), "Matches IPAddress.None");
            Assert.True(ext.MatchesHostname(IPAddress.IPv6Loopback.ToString()), "Matches IPAddress.IPv6Loopback");
            Assert.True(ext.MatchesHostname(IPAddress.Loopback.ToString()), "Matches IPAddress.Loopback");
        }

        [Fact]
        public static void MatchesDnsName()
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

            static void AssertMatches(X509SubjectAlternativeNameExtension ext, string target, bool expected)
            {
                if (expected)
                {
                    Assert.True(ext.MatchesHostname(target), $"Matches '{target}'");
                }
                else
                {
                    Assert.False(ext.MatchesHostname(target), $"Matches '{target}'");
                }
            }

            AssertMatches(ext, "foo", true);
            AssertMatches(ext, "fOo", true);
            AssertMatches(ext, "fOo.", true);
            AssertMatches(ext, ".fOo.", false);
            AssertMatches(ext, "BAR.fOo.", true);
            AssertMatches(ext, "BAR.foo", true);
            AssertMatches(ext, "baz.BAR.foo", false);
            AssertMatches(ext, "baz.BAR.foo.", false);
            AssertMatches(ext, "example.com", false);
        }
    }
}
