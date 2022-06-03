// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Net;
using System.Security.Cryptography.Asn1;
using System.Text;

namespace System.Security.Cryptography.X509Certificates
{
    public sealed class SubjectAlternativeNameBuilder
    {
        private static readonly IdnMapping s_idnMapping = new IdnMapping();

        // Because GeneralNames is a SEQUENCE, just make a rolling list, it doesn't need to be re-sorted.
        private readonly List<byte[]> _encodedNames = new List<byte[]>();
        private readonly AsnWriter _writer = new AsnWriter(AsnEncodingRules.DER);

        public void AddEmailAddress(string emailAddress)
        {
            if (string.IsNullOrEmpty(emailAddress))
                throw new ArgumentOutOfRangeException(nameof(emailAddress), SR.Arg_EmptyOrNullString);

            AddGeneralName(new GeneralNameAsn { Rfc822Name = emailAddress });
        }

        public void AddDnsName(string dnsName)
        {
            if (string.IsNullOrEmpty(dnsName))
                throw new ArgumentOutOfRangeException(nameof(dnsName), SR.Arg_EmptyOrNullString);

            AddGeneralName(new GeneralNameAsn { DnsName = s_idnMapping.GetAscii(dnsName) });
        }

        public void AddUri(Uri uri)
        {
            ArgumentNullException.ThrowIfNull(uri);

            AddGeneralName(new GeneralNameAsn { Uri = uri.AbsoluteUri.ToString() });
        }

        public void AddIpAddress(IPAddress ipAddress)
        {
            ArgumentNullException.ThrowIfNull(ipAddress);

            AddGeneralName(new GeneralNameAsn { IPAddress = ipAddress.GetAddressBytes() });
        }

        public void AddUserPrincipalName(string upn)
        {
            if (string.IsNullOrEmpty(upn))
                throw new ArgumentOutOfRangeException(nameof(upn), SR.Arg_EmptyOrNullString);

            _writer.Reset();
            _writer.WriteCharacterString(UniversalTagNumber.UTF8String, upn);
            byte[] otherNameValue = _writer.Encode();
            _writer.Reset();

            OtherNameAsn otherName = new OtherNameAsn
            {
                TypeId = Oids.UserPrincipalName,
                Value = otherNameValue,
            };

            AddGeneralName(new GeneralNameAsn { OtherName = otherName });
        }

        public X509Extension Build(bool critical = false)
        {
            _writer.Reset();

            using (_writer.PushSequence())
            {
                foreach (byte[] encodedName in _encodedNames)
                {
                    _writer.WriteEncodedValue(encodedName);
                }
            }

            byte[] encoded = _writer.Encode();
            _writer.Reset();

            return new X509Extension(Oids.SubjectAltName, encoded, critical);
        }

        private void AddGeneralName(GeneralNameAsn generalName)
        {
            try
            {
                // Verify that the general name can be serialized and store it.
                _writer.Reset();
                generalName.Encode(_writer);
                _encodedNames.Add(_writer.Encode());
                _writer.Reset();
            }
            catch (EncoderFallbackException)
            {
                throw new CryptographicException(SR.Cryptography_Invalid_IA5String);
            }
        }
    }
}
