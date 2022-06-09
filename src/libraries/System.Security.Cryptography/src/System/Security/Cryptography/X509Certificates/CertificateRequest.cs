// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Runtime.Versioning;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates.Asn1;
using Internal.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Represents an abstraction over the PKCS#10 CertificationRequestInfo and the X.509 TbsCertificate,
    /// allowing callers to create self-signed or chain-signed X.509 Public-Key Certificates, as well as
    /// create a certificate signing request blob to send to a Certificate Authority (CA).
    /// </summary>
    [UnsupportedOSPlatform("browser")]
    public sealed class CertificateRequest
    {
        private readonly AsymmetricAlgorithm? _key;
        private readonly X509SignatureGenerator? _generator;
        private readonly RSASignaturePadding? _rsaPadding;

        /// <summary>
        /// The X.500 Distinguished Name to use as the Subject in a created certificate or certificate request.
        /// </summary>
        public X500DistinguishedName SubjectName { get; }

        /// <summary>
        /// The X.509 Certificate Extensions to include in the certificate or certificate request.
        /// </summary>
        public Collection<X509Extension> CertificateExtensions { get; } = new Collection<X509Extension>();

        /// <summary>
        ///   Gets a collection representing attributes, other than the extension request attribute, to include
        ///   in a certificate request.
        /// </summary>
        /// <value>
        ///   A collection representing attributes, other than the extension request attribute, to include
        ///   in a certificate request
        /// </value>
        public Collection<AsnEncodedData> OtherRequestAttributes { get; } = new Collection<AsnEncodedData>();

        /// <summary>
        /// A <see cref="PublicKey" /> representation of the public key for the certificate or certificate request.
        /// </summary>
        public PublicKey PublicKey { get; }

        /// <summary>
        /// The hash algorithm to use when signing the certificate or certificate request.
        /// </summary>
        public HashAlgorithmName HashAlgorithm { get; }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, ECDSA key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The string representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   An ECDSA key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        /// <seealso cref="X500DistinguishedName(string)"/>
        public CertificateRequest(string subjectName, ECDsa key, HashAlgorithmName hashAlgorithm)
        {
            ArgumentNullException.ThrowIfNull(subjectName);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name, nameof(hashAlgorithm));

            SubjectName = new X500DistinguishedName(subjectName);

            _key = key;
            _generator = X509SignatureGenerator.CreateForECDsa(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, ECDSA key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The parsed representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   An ECDSA key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        public CertificateRequest(X500DistinguishedName subjectName, ECDsa key, HashAlgorithmName hashAlgorithm)
        {
            ArgumentNullException.ThrowIfNull(subjectName);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name, nameof(hashAlgorithm));

            SubjectName = subjectName;

            _key = key;
            _generator = X509SignatureGenerator.CreateForECDsa(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, RSA key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The string representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   An RSA key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        /// <param name="padding">
        ///   The RSA signature padding to apply if self-signing or being signed with an <see cref="X509Certificate2" />.
        /// </param>
        /// <seealso cref="X500DistinguishedName(string)"/>
        public CertificateRequest(string subjectName, RSA key, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            ArgumentNullException.ThrowIfNull(subjectName);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name, nameof(hashAlgorithm));
            ArgumentNullException.ThrowIfNull(padding);

            SubjectName = new X500DistinguishedName(subjectName);

            _key = key;
            _generator = X509SignatureGenerator.CreateForRSA(key, padding);
            _rsaPadding = padding;
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, RSA key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The parsed representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   An RSA key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        /// <param name="padding">
        ///   The RSA signature padding to apply if self-signing or being signed with an <see cref="X509Certificate2" />.
        /// </param>
        public CertificateRequest(
            X500DistinguishedName subjectName,
            RSA key,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding)
        {
            ArgumentNullException.ThrowIfNull(subjectName);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name, nameof(hashAlgorithm));
            ArgumentNullException.ThrowIfNull(padding);

            SubjectName = subjectName;

            _key = key;
            _generator = X509SignatureGenerator.CreateForRSA(key, padding);
            _rsaPadding = padding;
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, encoded public key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The parsed representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="publicKey">
        ///   The encoded representation of the public key to include in the certificate or certificate request.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        public CertificateRequest(X500DistinguishedName subjectName, PublicKey publicKey, HashAlgorithmName hashAlgorithm)
        {
            ArgumentNullException.ThrowIfNull(subjectName);
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name, nameof(hashAlgorithm));

            SubjectName = subjectName;
            PublicKey = publicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        ///   Create a CertificateRequest for the specified subject name, encoded public key, hash algorithm,
        ///   and RSA signature padding.
        /// </summary>
        /// <param name="subjectName">
        ///   The parsed representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="publicKey">
        ///   The encoded representation of the public key to include in the certificate or certificate request.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        /// <param name="rsaSignaturePadding">
        ///   The RSA signature padding to use when signing this request with an RSA certificate.
        /// </param>
        public CertificateRequest(
            X500DistinguishedName subjectName,
            PublicKey publicKey,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding? rsaSignaturePadding)
        {
            ArgumentNullException.ThrowIfNull(subjectName);
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name, nameof(hashAlgorithm));

            SubjectName = subjectName;
            PublicKey = publicKey;
            HashAlgorithm = hashAlgorithm;
            _rsaPadding = rsaSignaturePadding;
        }

        /// <summary>
        /// Create an ASN.1 DER-encoded PKCS#10 CertificationRequest object representing the current state
        /// of this object.
        /// </summary>
        /// <returns>A DER-encoded certificate signing request.</returns>
        /// <remarks>
        ///   When submitting a certificate signing request via a web browser, or other graphical or textual
        ///   interface, the input is frequently expected to be in the PEM (Privacy Enhanced Mail) format,
        ///   instead of the DER binary format.
        /// </remarks>
        /// <seealso cref="CreateSigningRequestPem()"/>
        public byte[] CreateSigningRequest()
        {
            if (_generator == null)
                throw new InvalidOperationException(SR.Cryptography_CertReq_NoKeyProvided);

            return CreateSigningRequest(_generator);
        }

        /// <summary>
        /// Create an ASN.1 DER-encoded PKCS#10 CertificationRequest representing the current state
        /// of this object using the provided signature generator.
        /// </summary>
        /// <param name="signatureGenerator">
        ///   A <see cref="X509SignatureGenerator"/> with which to sign the request.
        /// </param>
        /// <remarks>
        ///   When submitting a certificate signing request via a web browser, or other graphical or textual
        ///   interface, the input is frequently expected to be in the PEM (Privacy Enhanced Mail) format,
        ///   instead of the DER binary format.
        /// </remarks>
        /// <seealso cref="CreateSigningRequestPem(X509SignatureGenerator)"/>
        public byte[] CreateSigningRequest(X509SignatureGenerator signatureGenerator)
        {
            ArgumentNullException.ThrowIfNull(signatureGenerator);

            X501Attribute[] attributes = Array.Empty<X501Attribute>();
            bool hasExtensions = CertificateExtensions.Count > 0;

            if (OtherRequestAttributes.Count > 0 || hasExtensions)
            {
                attributes = new X501Attribute[OtherRequestAttributes.Count + (hasExtensions ? 1 : 0)];
            }

            int attrCount = 0;

            foreach (AsnEncodedData attr in OtherRequestAttributes)
            {
                if (attr is null)
                {
                    throw new InvalidOperationException("Something about a null attribute");
                }

                if (attr.Oid is null || attr.Oid.Value is null)
                {
                    throw new InvalidOperationException("Something about a null attr OID");
                }

                if (attr.Oid.Value == Oids.Pkcs9ExtensionRequest)
                {
                    throw new InvalidOperationException("Something about can't redefine the extensions attr");
                }

                Helpers.ValidateDer(attr.RawData);
                attributes[attrCount] = new X501Attribute(attr.Oid.Value, attr.RawData);
                attrCount++;
            }

            if (hasExtensions)
            {
                attributes[attrCount] = new Pkcs9ExtensionRequest(CertificateExtensions);
            }

            var requestInfo = new Pkcs10CertificationRequestInfo(SubjectName, PublicKey, attributes);
            return requestInfo.ToPkcs10Request(signatureGenerator, HashAlgorithm);
        }

        /// <summary>
        ///   Create a PEM-encoded PKCS#10 CertificationRequest representing the current state
        ///   of this object using the provided signature generator.
        /// </summary>
        /// <seealso cref="CreateSigningRequest()"/>
        public string CreateSigningRequestPem()
        {
            byte[] der = CreateSigningRequest();
            return PemEncoding.WriteString(PemLabels.Pkcs10CertificateRequest, der);
        }

        /// <summary>
        ///   Create a PEM-encoded PKCS#10 CertificationRequest representing the current state
        ///   of this object using the provided signature generator.
        /// </summary>
        /// <param name="signatureGenerator">
        ///   A <see cref="X509SignatureGenerator"/> with which to sign the request.
        /// </param>
        /// <seealso cref="CreateSigningRequest(X509SignatureGenerator)"/>
        public string CreateSigningRequestPem(X509SignatureGenerator signatureGenerator)
        {
            ArgumentNullException.ThrowIfNull(signatureGenerator);

            byte[] der = CreateSigningRequest(signatureGenerator);
            return PemEncoding.WriteString(PemLabels.Pkcs10CertificateRequest, der);
        }

        /// <summary>
        /// Create a self-signed certificate using the established subject, key, and optional
        /// extensions.
        /// </summary>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <returns>
        ///   An <see cref="X509Certificate2"/> with the specified values. The returned object will
        ///   assert <see cref="X509Certificate2.HasPrivateKey" />.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notAfter"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   A constructor was used which did not accept a signing key.
        /// </exception>>
        /// <exception cref="CryptographicException">
        ///   Other errors during the certificate creation process.
        /// </exception>
        public X509Certificate2 CreateSelfSigned(DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            if (notAfter < notBefore)
                throw new ArgumentException(SR.Cryptography_CertReq_DatesReversed);
            if (_key == null)
                throw new InvalidOperationException(SR.Cryptography_CertReq_NoKeyProvided);

            Debug.Assert(_generator != null);

            Span<byte> serialNumber = stackalloc byte[8];
            RandomNumberGenerator.Fill(serialNumber);

            using (X509Certificate2 certificate = Create(
                SubjectName,
                _generator,
                notBefore,
                notAfter,
                serialNumber))
            {
                RSA? rsa = _key as RSA;

                if (rsa != null)
                {
                    return certificate.CopyWithPrivateKey(rsa);
                }

                ECDsa? ecdsa = _key as ECDsa;

                if (ecdsa != null)
                {
                    return certificate.CopyWithPrivateKey(ecdsa);
                }
            }

            Debug.Fail($"Key was of no known type: {_key?.GetType().FullName ?? "null"}");
            throw new CryptographicException();
        }

        /// <summary>
        /// Create a certificate using the established subject, key, and optional extensions using
        /// the provided certificate as the issuer.
        /// </summary>
        /// <param name="issuerCertificate">
        ///   An X509Certificate2 instance representing the issuing Certificate Authority (CA).
        /// </param>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <param name="serialNumber">
        ///   The serial number to use for the new certificate. This value should be unique per issuer.
        ///   The value is interpreted as an unsigned (big) integer in big endian byte ordering.
        /// </param>
        /// <returns>
        ///   An <see cref="X509Certificate2"/> with the specified values. The returned object will
        ///   not assert <see cref="X509Certificate2.HasPrivateKey" />.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="issuerCertificate"/> is null.</exception>
        /// <exception cref="ArgumentException">
        ///   The <see cref="X509Certificate2.HasPrivateKey"/> value for <paramref name="issuerCertificate"/> is false.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   The type of signing key represented by <paramref name="issuerCertificate"/> could not be determined.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notBefore"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="serialNumber"/> is null or has length 0.</exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="issuerCertificate"/> has a different key algorithm than the requested certificate.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <paramref name="issuerCertificate"/> is an RSA certificate and this object was created via a constructor
        ///   which does not accept a <see cref="RSASignaturePadding"/> value.
        /// </exception>
        public X509Certificate2 Create(
            X509Certificate2 issuerCertificate,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            byte[] serialNumber)
        {
            // The null case for serialNumber is the same exception type and message as an empty array,
            // so just let it turn into the empty span and call the span overload.
            return Create(issuerCertificate, notBefore, notAfter, new ReadOnlySpan<byte>(serialNumber));
        }

        /// <summary>
        /// Create a certificate using the established subject, key, and optional extensions using
        /// the provided certificate as the issuer.
        /// </summary>
        /// <param name="issuerCertificate">
        ///   An X509Certificate2 instance representing the issuing Certificate Authority (CA).
        /// </param>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <param name="serialNumber">
        ///   The serial number to use for the new certificate. This value should be unique per issuer.
        ///   The value is interpreted as an unsigned (big) integer in big endian byte ordering.
        /// </param>
        /// <returns>
        ///   An <see cref="X509Certificate2"/> with the specified values. The returned object will
        ///   not assert <see cref="X509Certificate2.HasPrivateKey" />.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="issuerCertificate"/> is null.</exception>
        /// <exception cref="ArgumentException">
        ///   The <see cref="X509Certificate2.HasPrivateKey"/> value for <paramref name="issuerCertificate"/> is false.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   The type of signing key represented by <paramref name="issuerCertificate"/> could not be determined.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notBefore"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="serialNumber"/> has length 0.</exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="issuerCertificate"/> has a different key algorithm than the requested certificate.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <paramref name="issuerCertificate"/> is an RSA certificate and this object was created via a constructor
        ///   which does not accept a <see cref="RSASignaturePadding"/> value.
        /// </exception>
        public X509Certificate2 Create(
            X509Certificate2 issuerCertificate,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            ReadOnlySpan<byte> serialNumber)
        {
            ArgumentNullException.ThrowIfNull(issuerCertificate);

            if (!issuerCertificate.HasPrivateKey)
                throw new ArgumentException(SR.Cryptography_CertReq_IssuerRequiresPrivateKey, nameof(issuerCertificate));
            if (notAfter < notBefore)
                throw new ArgumentException(SR.Cryptography_CertReq_DatesReversed);
            if (serialNumber.IsEmpty)
                throw new ArgumentException(SR.Arg_EmptyOrNullArray, nameof(serialNumber));

            if (issuerCertificate.PublicKey.Oid.Value != PublicKey.Oid.Value)
            {
                throw new ArgumentException(
                    SR.Format(
                        SR.Cryptography_CertReq_AlgorithmMustMatch,
                        issuerCertificate.PublicKey.Oid.Value,
                        PublicKey.Oid.Value),
                    nameof(issuerCertificate));
            }

            DateTime notBeforeLocal = notBefore.LocalDateTime;
            if (notBeforeLocal < issuerCertificate.NotBefore)
            {
                throw new ArgumentException(
                    SR.Format(
                        SR.Cryptography_CertReq_NotBeforeNotNested,
                        notBeforeLocal,
                        issuerCertificate.NotBefore),
                    nameof(notBefore));
            }

            DateTime notAfterLocal = notAfter.LocalDateTime;

            // Round down to the second, since that's the cert accuracy.
            // This makes one method which uses the same DateTimeOffset for chained notAfters
            // not need to do the rounding locally.
            long notAfterLocalTicks = notAfterLocal.Ticks;
            long fractionalSeconds = notAfterLocalTicks % TimeSpan.TicksPerSecond;
            notAfterLocalTicks -= fractionalSeconds;
            notAfterLocal = new DateTime(notAfterLocalTicks, notAfterLocal.Kind);

            if (notAfterLocal > issuerCertificate.NotAfter)
            {
                throw new ArgumentException(
                    SR.Format(
                        SR.Cryptography_CertReq_NotAfterNotNested,
                        notAfterLocal,
                        issuerCertificate.NotAfter),
                    nameof(notAfter));
            }

            // Check the Basic Constraints and Key Usage extensions to help identify inappropriate certificates.
            // Note that this is not a security check. The system library backing X509Chain will use these same criteria
            // to determine if a chain is valid; and a user can easily call the X509SignatureGenerator overload to
            // bypass this validation.  We're simply helping them at signing time understand that they've
            // chosen the wrong cert.
            var basicConstraints = (X509BasicConstraintsExtension?)issuerCertificate.Extensions[Oids.BasicConstraints2];
            var keyUsage = (X509KeyUsageExtension?)issuerCertificate.Extensions[Oids.KeyUsage];

            if (basicConstraints == null)
                throw new ArgumentException(SR.Cryptography_CertReq_BasicConstraintsRequired, nameof(issuerCertificate));
            if (!basicConstraints.CertificateAuthority)
                throw new ArgumentException(SR.Cryptography_CertReq_IssuerBasicConstraintsInvalid, nameof(issuerCertificate));
            if (keyUsage != null && (keyUsage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
                throw new ArgumentException(SR.Cryptography_CertReq_IssuerKeyUsageInvalid, nameof(issuerCertificate));

            AsymmetricAlgorithm? key = null;
            string keyAlgorithm = issuerCertificate.GetKeyAlgorithm();
            X509SignatureGenerator generator;

            try
            {
                switch (keyAlgorithm)
                {
                    case Oids.Rsa:
                        if (_rsaPadding == null)
                        {
                            throw new InvalidOperationException(SR.Cryptography_CertReq_RSAPaddingRequired);
                        }

                        RSA? rsa = issuerCertificate.GetRSAPrivateKey();
                        key = rsa;
                        generator = X509SignatureGenerator.CreateForRSA(rsa!, _rsaPadding);
                        break;
                    case Oids.EcPublicKey:
                        ECDsa? ecdsa = issuerCertificate.GetECDsaPrivateKey();
                        key = ecdsa;
                        generator = X509SignatureGenerator.CreateForECDsa(ecdsa!);
                        break;
                    default:
                        throw new ArgumentException(
                            SR.Format(SR.Cryptography_UnknownKeyAlgorithm, keyAlgorithm),
                            nameof(issuerCertificate));
                }

                return Create(issuerCertificate.SubjectName, generator, notBefore, notAfter, serialNumber);
            }
            finally
            {
                key?.Dispose();
            }
        }

        /// <summary>
        /// Sign the current certificate request to create a chain-signed or self-signed certificate.
        /// </summary>
        /// <param name="issuerName">The X500DistinguishedName for the Issuer</param>
        /// <param name="generator">
        ///   An <see cref="X509SignatureGenerator"/> representing the issuing certificate authority.
        /// </param>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <param name="serialNumber">
        ///   The serial number to use for the new certificate. This value should be unique per issuer.
        ///   The value is interpreted as an unsigned (big) integer in big endian byte ordering.
        /// </param>
        /// <returns>
        ///   An <see cref="X509Certificate2"/> with the specified values. The returned object will
        ///   not assert <see cref="X509Certificate2.HasPrivateKey" />.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="issuerName"/> is null.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="generator"/> is null.</exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notBefore"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="serialNumber"/> is null or has length 0.</exception>
        /// <exception cref="CryptographicException">Any error occurs during the signing operation.</exception>
        public X509Certificate2 Create(
            X500DistinguishedName issuerName,
            X509SignatureGenerator generator,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            byte[] serialNumber)
        {
            // The null case for serialNumber is the same exception type and message as an empty array,
            // so just let it turn into the empty span and call the span overload.
            return Create(issuerName, generator, notBefore, notAfter, new ReadOnlySpan<byte>(serialNumber));
        }

        /// <summary>
        /// Sign the current certificate request to create a chain-signed or self-signed certificate.
        /// </summary>
        /// <param name="issuerName">The X500DistinguishedName for the Issuer</param>
        /// <param name="generator">
        ///   An <see cref="X509SignatureGenerator"/> representing the issuing certificate authority.
        /// </param>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <param name="serialNumber">
        ///   The serial number to use for the new certificate. This value should be unique per issuer.
        ///   The value is interpreted as an unsigned (big) integer in big endian byte ordering.
        /// </param>
        /// <returns>
        ///   An <see cref="X509Certificate2"/> with the specified values. The returned object will
        ///   not assert <see cref="X509Certificate2.HasPrivateKey" />.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="issuerName"/> is null.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="generator"/> is null.</exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notBefore"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="serialNumber"/> has length 0.</exception>
        /// <exception cref="CryptographicException">Any error occurs during the signing operation.</exception>
        public X509Certificate2 Create(
            X500DistinguishedName issuerName,
            X509SignatureGenerator generator,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            ReadOnlySpan<byte> serialNumber)
        {
            ArgumentNullException.ThrowIfNull(issuerName);
            ArgumentNullException.ThrowIfNull(generator);

            if (notAfter < notBefore)
                throw new ArgumentException(SR.Cryptography_CertReq_DatesReversed);
            if (serialNumber == null || serialNumber.Length < 1)
                throw new ArgumentException(SR.Arg_EmptyOrNullArray, nameof(serialNumber));

            byte[] signatureAlgorithm = generator.GetSignatureAlgorithmIdentifier(HashAlgorithm);
            AlgorithmIdentifierAsn signatureAlgorithmAsn;

            // Deserialization also does validation of the value (except for Parameters, which have to be validated separately).
            signatureAlgorithmAsn = AlgorithmIdentifierAsn.Decode(signatureAlgorithm, AsnEncodingRules.DER);
            if (signatureAlgorithmAsn.Parameters.HasValue)
            {
                Helpers.ValidateDer(signatureAlgorithmAsn.Parameters.Value.Span);
            }

            ArraySegment<byte> normalizedSerial = NormalizeSerialNumber(serialNumber);

            TbsCertificateAsn tbsCertificate = new TbsCertificateAsn
            {
                Version = 2,
                SerialNumber = normalizedSerial,
                SignatureAlgorithm = signatureAlgorithmAsn,
                Issuer = issuerName.RawData,
                SubjectPublicKeyInfo = new SubjectPublicKeyInfoAsn
                {
                    Algorithm = new AlgorithmIdentifierAsn
                    {
                        Algorithm = PublicKey.Oid!.Value!,
                        Parameters = PublicKey.EncodedParameters.RawData,
                    },
                    SubjectPublicKey = PublicKey.EncodedKeyValue.RawData,
                },
                Validity = new ValidityAsn(notBefore, notAfter),
                Subject = SubjectName.RawData,
            };

            if (CertificateExtensions.Count > 0)
            {
                HashSet<string?> usedOids = new HashSet<string?>(CertificateExtensions.Count);
                List<X509ExtensionAsn> extensionAsns = new List<X509ExtensionAsn>(CertificateExtensions.Count);

                foreach (X509Extension extension in CertificateExtensions)
                {
                    if (extension == null)
                    {
                        continue;
                    }

                    if (!usedOids.Add(extension.Oid!.Value))
                    {
                        throw new InvalidOperationException(
                            SR.Format(SR.Cryptography_CertReq_DuplicateExtension, extension.Oid.Value));
                    }

                    extensionAsns.Add(new X509ExtensionAsn(extension));
                }

                // Do not include the extensions sequence at all if there are no
                // extensions, per RFC 5280:
                // "If present, this field is a SEQUENCE of one or more certificate extensions"
                if (extensionAsns.Count > 0)
                {
                    tbsCertificate.Extensions = extensionAsns.ToArray();
                }
            }

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            tbsCertificate.Encode(writer);

            byte[] encodedTbsCertificate = writer.Encode();
            writer.Reset();

            CertificateAsn certificate = new CertificateAsn
            {
                TbsCertificate = tbsCertificate,
                SignatureAlgorithm = signatureAlgorithmAsn,
                SignatureValue = generator.SignData(encodedTbsCertificate, HashAlgorithm),
            };

            certificate.Encode(writer);
            X509Certificate2 ret = new X509Certificate2(writer.Encode());
            CryptoPool.Return(normalizedSerial);
            return ret;
        }

        public static unsafe CertificateRequest LoadCertificateRequest(
            ReadOnlySpan<byte> pkcs10,
            HashAlgorithmName signerHashAlgorithm,
            out int bytesConsumed,
            bool skipSignatureValidation = false,
            bool unsafeLoadCertificateExtensions = false,
            RSASignaturePadding? signerSignaturePadding = null)
        {
            try
            {
                AsnValueReader outer = new AsnValueReader(pkcs10, AsnEncodingRules.DER);
                int encodedLength = outer.PeekEncodedValue().Length;

                AsnValueReader pkcs10Asn = outer.ReadSequence();
                CertificateRequest req;

                fixed (byte* p10ptr = pkcs10)
                {
                    using (PointerMemoryManager<byte> manager = new PointerMemoryManager<byte>(p10ptr, encodedLength))
                    {
                        ReadOnlyMemory<byte> rebind = manager.Memory;
                        ReadOnlySpan<byte> encodedRequestInfo = pkcs10Asn.PeekEncodedValue();
                        CertificationRequestInfoAsn requestInfo;
                        AlgorithmIdentifierAsn algorithmIdentifier;
                        ReadOnlySpan<byte> signature;
                        int signatureUnusedBitCount;

                        CertificationRequestInfoAsn.Decode(ref pkcs10Asn, rebind, out requestInfo);
                        AlgorithmIdentifierAsn.Decode(ref pkcs10Asn, rebind, out algorithmIdentifier);

                        if (!pkcs10Asn.TryReadPrimitiveBitString(out signatureUnusedBitCount, out signature))
                        {
                            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                        }

                        pkcs10Asn.ThrowIfNotEmpty();

                        if (requestInfo.Version != 0)
                        {
                            throw new CryptographicException("Something about a request from the future");
                        }

                        PublicKey publicKey = PublicKey.DecodeSubjectPublicKeyInfo(ref requestInfo.SubjectPublicKeyInfo);

                        if (!skipSignatureValidation)
                        {
                            // None of the supported signature algorithms support signatures that are not full bytes.
                            // So, shortcut the verification on the bit length
                            if (signatureUnusedBitCount != 0 ||
                                !VerifyX509Signature(encodedRequestInfo, signature, publicKey, algorithmIdentifier))
                            {
                                throw new CryptographicException("Signature didn't work");
                            }
                        }

                        X500DistinguishedName subject = new X500DistinguishedName(requestInfo.Subject.Span);

                        req = new CertificateRequest(
                            subject,
                            publicKey,
                            signerHashAlgorithm,
                            signerSignaturePadding);

                        if (requestInfo.Attributes is not null)
                        {
                            bool foundCertExt = false;

                            foreach (AttributeAsn attr in requestInfo.Attributes)
                            {
                                if (attr.AttrType == Oids.Pkcs9ExtensionRequest)
                                {
                                    if (foundCertExt)
                                    {
                                        throw new CryptographicException("Too many certificate extension requests");
                                    }

                                    foundCertExt = true;

                                    if (attr.AttrValues.Length != 1)
                                    {
                                        throw new CryptographicException("Invalid certificate extensions request");
                                    }

                                    AsnValueReader extsReader = new AsnValueReader(
                                        attr.AttrValues[0].Span,
                                        AsnEncodingRules.DER);

                                    AsnValueReader exts = extsReader.ReadSequence();
                                    extsReader.ThrowIfNotEmpty();

                                    while (exts.HasData)
                                    {
                                        X509ExtensionAsn.Decode(ref exts, rebind, out X509ExtensionAsn extAsn);

                                        if (unsafeLoadCertificateExtensions)
                                        {
                                            X509Extension ext = new X509Extension(
                                                extAsn.ExtnId,
                                                extAsn.ExtnValue.Span,
                                                extAsn.Critical);

                                            X509Extension? rich =
                                                X509Certificate2.CreateCustomExtensionIfAny(extAsn.ExtnId);

                                            if (rich is not null)
                                            {
                                                rich.CopyFrom(ext);
                                                req.CertificateExtensions.Add(rich);
                                            }
                                            else
                                            {
                                                req.CertificateExtensions.Add(ext);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    foreach (ReadOnlyMemory<byte> val in attr.AttrValues)
                                    {
                                        req.OtherRequestAttributes.Add(
                                            new AsnEncodedData(attr.AttrType, val.Span));
                                    }
                                }
                            }
                        }
                    }
                }

                bytesConsumed = encodedLength;
                return req;
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }

        private static ArraySegment<byte> NormalizeSerialNumber(ReadOnlySpan<byte> serialNumber)
        {
            byte[] newSerialNumber;

            if (serialNumber[0] >= 0x80)
            {
                // Keep the serial number unsigned by prepending a zero.
                newSerialNumber = CryptoPool.Rent(serialNumber.Length + 1);
                newSerialNumber[0] = 0;
                serialNumber.CopyTo(newSerialNumber.AsSpan(1));
                return new ArraySegment<byte>(newSerialNumber, 0, serialNumber.Length + 1);
            }

            // Strip any unnecessary zeros from the beginning.
            int leadingZeros = 0;
            while (leadingZeros < serialNumber.Length - 1 && serialNumber[leadingZeros] == 0 && serialNumber[leadingZeros + 1] < 0x80)
            {
                leadingZeros++;
            }

            int contentLength = serialNumber.Length - leadingZeros;
            newSerialNumber = CryptoPool.Rent(contentLength);
            serialNumber.Slice(leadingZeros).CopyTo(newSerialNumber);
            return new ArraySegment<byte>(newSerialNumber, 0, contentLength);
        }

        private static bool VerifyX509Signature(
            ReadOnlySpan<byte> toBeSigned,
            ReadOnlySpan<byte> signature,
            PublicKey publicKey,
            AlgorithmIdentifierAsn algorithmIdentifier)
        {
            RSA? rsa = publicKey.GetRSAPublicKey();
            ECDsa? ecdsa = publicKey.GetECDsaPublicKey();

            try
            {
                HashAlgorithmName hashAlg;

                if (algorithmIdentifier.Algorithm == Oids.RsaPss)
                {
                    if (rsa is null || !algorithmIdentifier.Parameters.HasValue)
                    {
                        return false;
                    }

                    PssParamsAsn pssParams = PssParamsAsn.Decode(
                        algorithmIdentifier.Parameters.GetValueOrDefault(),
                        AsnEncodingRules.DER);

                    if (pssParams.TrailerField != 1 ||
                        !pssParams.HashAlgorithm.HasNullEquivalentParameters() ||
                        pssParams.MaskGenAlgorithm.Algorithm != Oids.Mgf1 ||
                        !pssParams.MaskGenAlgorithm.Parameters.HasValue)
                    {
                        return false;
                    }

                    AlgorithmIdentifierAsn mgfParams = AlgorithmIdentifierAsn.Decode(
                        pssParams.MaskGenAlgorithm.Parameters.GetValueOrDefault(),
                        AsnEncodingRules.DER);

                    if (mgfParams.Algorithm != pssParams.HashAlgorithm.Algorithm ||
                        !mgfParams.HasNullEquivalentParameters())
                    {
                        return false;
                    }

                    switch (pssParams.HashAlgorithm.Algorithm)
                    {
                        case Oids.Sha256:
                            if (pssParams.SaltLength != SHA256.HashSizeInBytes)
                            {
                                return false;
                            }

                            hashAlg = HashAlgorithmName.SHA256;
                            break;
                        case Oids.Sha384:
                            if (pssParams.SaltLength != SHA384.HashSizeInBytes)
                            {
                                return false;
                            }

                            hashAlg = HashAlgorithmName.SHA384;
                            break;
                        case Oids.Sha512:
                            if (pssParams.SaltLength != SHA512.HashSizeInBytes)
                            {
                                return false;
                            }

                            hashAlg = HashAlgorithmName.SHA512;
                            break;
                        case Oids.Sha1:
                            if (pssParams.SaltLength != SHA1.HashSizeInBytes)
                            {
                                return false;
                            }

                            hashAlg = HashAlgorithmName.SHA1;
                            break;
                        default:
                            return false;
                    }

                    return rsa.VerifyData(
                        toBeSigned,
                        signature,
                        hashAlg,
                        RSASignaturePadding.Pss);
                }

                // All remaining algorithms have no defined parameters
                if (!algorithmIdentifier.HasNullEquivalentParameters())
                {
                    return false;
                }

                switch (algorithmIdentifier.Algorithm)
                {
                    case Oids.RsaPkcs1Sha256:
                    case Oids.ECDsaWithSha256:
                        hashAlg = HashAlgorithmName.SHA256;
                        break;
                    case Oids.RsaPkcs1Sha384:
                    case Oids.ECDsaWithSha384:
                        hashAlg = HashAlgorithmName.SHA384;
                        break;
                    case Oids.RsaPkcs1Sha512:
                    case Oids.ECDsaWithSha512:
                        hashAlg = HashAlgorithmName.SHA512;
                        break;
                    case Oids.RsaPkcs1Sha1:
                    case Oids.ECDsaWithSha1:
                        hashAlg = HashAlgorithmName.SHA1;
                        break;
                    default:
                        return false;
                }

                switch (algorithmIdentifier.Algorithm)
                {
                    case Oids.RsaPkcs1Sha256:
                    case Oids.RsaPkcs1Sha384:
                    case Oids.RsaPkcs1Sha512:
                    case Oids.RsaPkcs1Sha1:
                        if (rsa is null)
                        {
                            return false;
                        }

                        return rsa.VerifyData(toBeSigned, signature, hashAlg, RSASignaturePadding.Pkcs1);
                    case Oids.ECDsaWithSha256:
                    case Oids.ECDsaWithSha384:
                    case Oids.ECDsaWithSha512:
                    case Oids.ECDsaWithSha1:
                        if (ecdsa is null)
                        {
                            return false;
                        }

                        return ecdsa.VerifyData(toBeSigned, signature, hashAlg);
                    default:
                        Debug.Fail($"Algorithm ID {algorithmIdentifier.Algorithm} was in the first switch, but not the second");
                        return false;
                }
            }
            catch (AsnContentException)
            {
                return false;
            }
            finally
            {
                rsa?.Dispose();
                ecdsa?.Dispose();
            }
        }
    }
}
