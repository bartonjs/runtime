// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;

namespace System.Security.Cryptography.X509Certificates
{
    public sealed class X500RelativeDistinguishedName
    {
        public ReadOnlyMemory<byte> RawData { get; }
        public bool HasMultipleValues { get; }
        public Oid? SingleValueType { get; }
        public string? SingleValueValue { get; }

        internal X500RelativeDistinguishedName(ReadOnlyMemory<byte> rawData)
        {
            RawData = rawData;

            AsnValueReader outer = new AsnValueReader(rawData.Span, AsnEncodingRules.DER);

            // Windows does not enforce the sort order on multi-value RDNs.
            AsnValueReader rdn = outer.ReadSetOf(skipSortOrderValidation: true);
            AsnValueReader typeAndValue = rdn.ReadSequence();

            Oid firstType = Oids.GetSharedOrNewOid(ref typeAndValue);
            string firstValue = typeAndValue.ReadAnyAsnString();
            typeAndValue.ThrowIfNotEmpty();

            if (rdn.HasData)
            {
                HasMultipleValues = true;

                while (rdn.HasData)
                {
                    typeAndValue = rdn.ReadSequence();
                    Oids.GetSharedOrNewOid(ref typeAndValue);
                    typeAndValue.ReadAnyAsnString();
                    typeAndValue.ThrowIfNotEmpty();
                }
            }
            else
            {
                SingleValueType = firstType;
                SingleValueValue = firstValue;
            }
        }
    }
}
