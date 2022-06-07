// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Formats.Asn1;

namespace System.Security.Cryptography.X509Certificates
{
    public sealed class X500DistinguishedName : AsnEncodedData
    {
        private volatile string? _lazyDistinguishedName;
        private List<(Oid, string)>? _parsedAttributes;

        public X500DistinguishedName(byte[] encodedDistinguishedName)
            : base(new Oid(null, null), encodedDistinguishedName)
        {
        }

        /// <summary>
        ///   Initializes a new instance of the <see cref="X500DistinguishedName"/>
        ///   class using information from the provided data.
        /// </summary>
        /// <param name="encodedDistinguishedName">
        ///   The encoded distinguished name.
        /// </param>
        /// <seealso cref="Encode"/>
        public X500DistinguishedName(ReadOnlySpan<byte> encodedDistinguishedName)
            : base(new Oid(null, null), encodedDistinguishedName)
        {
        }

        public X500DistinguishedName(AsnEncodedData encodedDistinguishedName)
            : base(encodedDistinguishedName)
        {
        }

        public X500DistinguishedName(X500DistinguishedName distinguishedName)
            : base(distinguishedName)
        {
            _lazyDistinguishedName = distinguishedName.Name;
        }

        public X500DistinguishedName(string distinguishedName)
            : this(distinguishedName, X500DistinguishedNameFlags.Reversed)
        {
        }

        public X500DistinguishedName(string distinguishedName, X500DistinguishedNameFlags flag)
            : base(new Oid(null, null), Encode(distinguishedName, flag))
        {
            _lazyDistinguishedName = distinguishedName;
        }

        public string Name
        {
            get
            {
                string? name = _lazyDistinguishedName;
                if (name == null)
                {
                    name = _lazyDistinguishedName = Decode(X500DistinguishedNameFlags.Reversed);
                }
                return name;
            }
        }

        public string Decode(X500DistinguishedNameFlags flag)
        {
            ThrowIfInvalid(flag);
            return X509Pal.Instance.X500DistinguishedNameDecode(RawData, flag);
        }

        public override string Format(bool multiLine)
        {
            return X509Pal.Instance.X500DistinguishedNameFormat(RawData, multiLine);
        }

        /// <summary>
        ///   Enumerates over the X500DistinguishedName, showing the attribute type identifier and attribute value
        ///   at each step in the enumeration.
        /// </summary>
        /// <param name="reversed">
        ///   <see langword="true" /> to enumerate in the order used by <see cref="Name"/>;
        ///   <see langword="false" /> to enumerate in the declared order.
        /// </param>
        /// <returns>
        ///   An enumerator that iterates over the attributes in the X.500 Dinstinguished Name.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   The X.500 Name is not a proper DER-encoded X.500 Name value, or the X.500 Name contains
        ///   multiple-value Relative Distinguished Names.
        /// </exception>
        public IEnumerable<(Oid AttributeType, string Value)> EnumerateSimpleAttributes(bool reversed = true)
        {
            List<(Oid, string)> parsedAttributes = _parsedAttributes ??= ParseAttributes(RawData);

            return EnumerateParsedAttributes(parsedAttributes, reversed);
        }

        private static byte[] Encode(string distinguishedName, X500DistinguishedNameFlags flags)
        {
            ArgumentNullException.ThrowIfNull(distinguishedName);

            ThrowIfInvalid(flags);

            return X509Pal.Instance.X500DistinguishedNameEncode(distinguishedName, flags);
        }

        private static void ThrowIfInvalid(X500DistinguishedNameFlags flags)
        {
            // All values or'ed together. Change this if you add values to the enumeration.
            uint allFlags = 0x71F1;
            uint dwFlags = (uint)flags;
            if ((dwFlags & ~allFlags) != 0)
                throw new ArgumentException(SR.Format(SR.Arg_EnumIllegalVal, "flag"));
        }

        private static IEnumerable<(Oid AttributeType, string AttributeValue)> EnumerateParsedAttributes(
            List<(Oid, string)> parsedAttributes,
            bool reversed)
        {
            if (reversed)
            {
                for (int i = parsedAttributes.Count - 1; i >= 0; i--)
                {
                    yield return parsedAttributes[i];
                }
            }
            else
            {
                for (int i = 0; i < parsedAttributes.Count; i++)
                {
                    yield return parsedAttributes[i];
                }
            }
        }

        private static List<(Oid, string)> ParseAttributes(byte[] rawData)
        {
            List<(Oid, string)>? parsedAttributes = null;

            try
            {
                AsnValueReader outer = new AsnValueReader(rawData, AsnEncodingRules.DER);
                AsnValueReader sequence = outer.ReadSequence();
                outer.ThrowIfNotEmpty();

                while (sequence.HasData)
                {
                    // If the set has multiple values we're going to throw, so don't bother checking that they're sorted.
                    AsnValueReader set = sequence.ReadSetOf(skipSortOrderValidation: true);
                    AsnValueReader typeAndValue = set.ReadSequence();
                    set.ThrowIfNotEmpty();

                    string type = typeAndValue.ReadObjectIdentifier();
                    string value = typeAndValue.ReadAnyAsnString();
                    typeAndValue.ThrowIfNotEmpty();

                    (parsedAttributes ??= new List<(Oid, string)>()).Add((new Oid(type, null), value));
                }
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }

            return parsedAttributes ?? new List<(Oid, string)>();
        }
    }
}
