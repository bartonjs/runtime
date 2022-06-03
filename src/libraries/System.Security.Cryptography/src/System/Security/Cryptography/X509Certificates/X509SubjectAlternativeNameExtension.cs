// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography.X509Certificates
{
    public class X509SubjectAlternativeNameExtension : X509Extension
    {
        private List<GeneralNameAsn>? _decoded;

        public X509SubjectAlternativeNameExtension() : base(Oids.SubjectAltName)
        {
        }

        public X509SubjectAlternativeNameExtension(byte[] rawData, bool critical = false)
            : base(Oids.SubjectAltName, rawData, critical)
        {
            _decoded = Decode(RawData);
        }

        public X509SubjectAlternativeNameExtension(ReadOnlySpan<byte> rawData, bool critical = false)
            : base(Oids.SubjectAltName, rawData, critical)
        {
            _decoded = Decode(RawData);
        }

        public override void CopyFrom(AsnEncodedData asnEncodedData)
        {
            base.CopyFrom(asnEncodedData);
            _decoded = null;
        }

        public bool MatchesHostname(string hostname)
        {
            ArgumentNullException.ThrowIfNull(hostname);

            if (hostname.Length == 0)
            {
                return false;
            }

            if (IPAddress.TryParse(hostname, out IPAddress? ipAddress))
            {
                // Big enough for IPv6
                Span<byte> encodedAddr = stackalloc byte[16];

                if (!ipAddress.TryWriteBytes(encodedAddr, out int written))
                {
                    return false;
                }

                ReadOnlySpan<byte> match = encodedAddr.Slice(0, written);

                List<GeneralNameAsn> decoded = (_decoded ??= Decode(RawData));

                foreach (GeneralNameAsn item in decoded)
                {
                    if (item.IPAddress.HasValue)
                    {
                        if (item.IPAddress.GetValueOrDefault().Span.SequenceEqual(match))
                        {
                            return true;
                        }
                    }
                }
            }
            else
            {
                ReadOnlySpan<char> match = hostname;

                if (hostname.EndsWith('.'))
                {
                    match = match.Slice(0, match.Length - 1);

                    if (match.IsEmpty)
                    {
                        return false;
                    }
                }

                ReadOnlySpan<char> afterFirstDot = default;
                int firstDot = match.IndexOf('.');

                if (firstDot == 0)
                {
                    return false;
                }

                if (firstDot > 0)
                {
                    afterFirstDot = match.Slice(firstDot + 1);
                }

                foreach (string embedded in EnumerateDnsNames())
                {
                    if (embedded.Length == 0)
                    {
                        continue;
                    }

                    ReadOnlySpan<char> embeddedSpan = embedded;

                    if (embedded.EndsWith('.'))
                    {
                        embeddedSpan = embeddedSpan.Slice(0, embeddedSpan.Length - 1);
                    }

                    if (embeddedSpan.StartsWith("*.") && embeddedSpan.Length > 2)
                    {
                        if (embeddedSpan.Slice(2).Equals(afterFirstDot, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                    else if (embeddedSpan.Equals(match, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public IEnumerable<string> EnumerateDnsNames()
        {
            List<GeneralNameAsn> decoded = (_decoded ??= Decode(RawData));

            return EnumerateDnsNames(decoded);
        }

        private static IEnumerable<string> EnumerateDnsNames(List<GeneralNameAsn> decoded)
        {
            foreach (GeneralNameAsn item in decoded)
            {
                if (item.DnsName is not null)
                {
                    yield return item.DnsName;
                }
            }
        }

        public IEnumerable<IPAddress> EnumerateIPAddresses()
        {
            List<GeneralNameAsn> decoded = (_decoded ??= Decode(RawData));

            return EnumerateIPAddresses(decoded);
        }

        private static IEnumerable<IPAddress> EnumerateIPAddresses(List<GeneralNameAsn> decoded)
        {
            foreach (GeneralNameAsn item in decoded)
            {
                if (item.IPAddress.HasValue)
                {
                    ReadOnlySpan<byte> value = item.IPAddress.GetValueOrDefault().Span;

                    if (value.Length is 4 or 16)
                    {
                        yield return new IPAddress(value);
                    }
                }
            }
        }

        private static List<GeneralNameAsn> Decode(ReadOnlySpan<byte> rawData)
        {
            AsnValueReader outer = new AsnValueReader(rawData, AsnEncodingRules.DER);
            AsnValueReader sequence = outer.ReadSequence();
            outer.ThrowIfNotEmpty();

            List<GeneralNameAsn> decoded = new List<GeneralNameAsn>();

            while (sequence.HasData)
            {
                GeneralNameAsn.Decode(ref sequence, default, out GeneralNameAsn item);
                decoded.Add(item);
            }

            return decoded;
        }
    }
}
