// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;

namespace System.Security.Cryptography
{
    /// <summary>
    ///   A managed implementation of HPKE (RFC 9180) for DHKEM with NIST P-256/P-384
    ///   curves, HKDF-SHA256/SHA384, and AES-GCM/ChaCha20Poly1305 AEAD.
    ///   This is a proof-of-concept to validate the public API shape.
    /// </summary>
    internal sealed class HpkeManaged : Hpke
    {
        private readonly ECDiffieHellman? _privateKey;
        private readonly ECParameters _publicKeyParameters;

        private HpkeManaged(HpkeSuite suite, ECDiffieHellman? privateKey, ECParameters publicKeyParameters)
            : base(suite)
        {
            _privateKey = privateKey;
            _publicKeyParameters = publicKeyParameters;
        }

        internal static HpkeManaged GenerateKeyManaged(HpkeSuite suite)
        {
            ECCurve curve = GetCurve(suite);
            ECDiffieHellman key = ECDiffieHellman.Create(curve);

            return new HpkeManaged(suite, key, key.ExportParameters(includePrivateParameters: false));
        }

        internal static HpkeManaged ImportEncapsulationKeyManaged(HpkeSuite suite, ReadOnlySpan<byte> source)
        {
            ECParameters parameters = DeserializePublicKey(suite, source);

            return new HpkeManaged(suite, privateKey: null, parameters);
        }

        internal static HpkeManaged ImportDecapsulationKeyManaged(HpkeSuite suite, ReadOnlySpan<byte> source)
        {
            ECCurve curve = GetCurve(suite);

            ECParameters parameters = new ECParameters
            {
                Curve = curve,
                D = source.Slice(0, suite.DecapsulationKeySizeInBytes).ToArray(),
            };

            ECDiffieHellman key = ECDiffieHellman.Create(parameters);
            ECParameters pub = key.ExportParameters(includePrivateParameters: false);

            return new HpkeManaged(suite, key, pub);
        }

        private ECDiffieHellman GetPrivateKey()
        {
            ThrowIfDisposed();

            return _privateKey ?? throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
        }

        private ECParameters GetPublicKeyParameters()
        {
            ThrowIfDisposed();
            return _publicKeyParameters;
        }

        private static ECParameters ExportPublicKeyParameters(Hpke key, HpkeSuite suite)
        {
            if (key is HpkeManaged managed)
            {
                return managed.GetPublicKeyParameters();
            }

            return DeserializePublicKey(suite, key.ExportEncapsulationKey());
        }

        protected override void ExportEncapsulationKeyCore(Span<byte> destination)
        {
            SerializePublicKey(_publicKeyParameters, destination);
        }

        protected override void ExportDecapsulationKeyCore(Span<byte> destination)
        {
            if (_privateKey is null)
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }

            ECParameters parameters = _privateKey.ExportParameters(includePrivateParameters: true);
            parameters.D.CopyTo(destination);
        }

        protected override void SealCore(
            ReadOnlySpan<byte> plaintext,
            Span<byte> encapsulatedKey,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> aad,
            ReadOnlySpan<byte> info)
        {
            // SetupBaseS: (shared_secret, enc) = Encap(pkR), then KeySchedule, then Seal
            ECCurve curve = GetCurve(Suite);
            using (ECDiffieHellman ephemeral = ECDiffieHellman.Create(curve))
            {
                // enc = SerializePublicKey(pkE)
                ECParameters ephPub = ephemeral.ExportParameters(includePrivateParameters: false);
                SerializePublicKey(ephPub, encapsulatedKey);

                // DH(skE, pkR)
                using (ECDiffieHellman recipientPub = ECDiffieHellman.Create(_publicKeyParameters))
                {
                    byte[] dh = ephemeral.DeriveRawSecretAgreement(recipientPub.PublicKey);

                    // kem_context = enc || SerializePublicKey(pkR)
                    byte[] pkRm = new byte[Suite.EncapsulationKeySizeInBytes];
                    SerializePublicKey(_publicKeyParameters, pkRm);

                    byte[] kemContext = new byte[encapsulatedKey.Length + pkRm.Length];
                    encapsulatedKey.CopyTo(kemContext);
                    pkRm.CopyTo(kemContext.AsSpan(encapsulatedKey.Length));

                    // shared_secret = ExtractAndExpand(dh, kem_context)
                    byte[] sharedSecret = ExtractAndExpand(Suite, dh, kemContext);

                    // KeySchedule(mode_base, shared_secret, info, "", "")
                    DeriveKeyScheduleAndSeal(Suite, sharedSecret, info, plaintext, ciphertext, aad);
                }
            }
        }

        protected override void OpenCore(
            ReadOnlySpan<byte> encapsulatedKey,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> aad,
            ReadOnlySpan<byte> info)
        {
            if (_privateKey is null)
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }

            // SetupBaseR: shared_secret = Decap(enc, skR), then KeySchedule, then Open
            // pkE = DeserializePublicKey(enc)
            ECParameters ephPub = DeserializePublicKey(Suite, encapsulatedKey);
            using (ECDiffieHellman ephPublicKey = ECDiffieHellman.Create(ephPub))
            {
                // DH(skR, pkE)
                byte[] dh = _privateKey.DeriveRawSecretAgreement(ephPublicKey.PublicKey);

                // kem_context = enc || SerializePublicKey(pk(skR))
                byte[] pkRm = new byte[Suite.EncapsulationKeySizeInBytes];
                SerializePublicKey(_publicKeyParameters, pkRm);

                byte[] kemContext = new byte[encapsulatedKey.Length + pkRm.Length];
                encapsulatedKey.CopyTo(kemContext);
                pkRm.CopyTo(kemContext.AsSpan(encapsulatedKey.Length));

                // shared_secret = ExtractAndExpand(dh, kem_context)
                byte[] sharedSecret = ExtractAndExpand(Suite, dh, kemContext);

                // KeySchedule(mode_base, shared_secret, info, "", "")
                DeriveKeyScheduleAndOpen(Suite, sharedSecret, info, ciphertext, plaintext, aad);
            }
        }

        protected override HpkeSenderContext SetupSenderCore(
            Span<byte> encapsulatedKey,
            ReadOnlySpan<byte> info)
        {
            return SetupSenderPskCore(encapsulatedKey, info, default, default);
        }

        protected override HpkeSenderContext SetupSenderPskCore(
            Span<byte> encapsulatedKey,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId)
        {
            ECCurve curve = GetCurve(Suite);
            using (ECDiffieHellman ephemeral = ECDiffieHellman.Create(curve))
            {
                ECParameters ephPub = ephemeral.ExportParameters(includePrivateParameters: false);
                SerializePublicKey(ephPub, encapsulatedKey);

                using (ECDiffieHellman recipientPub = ECDiffieHellman.Create(_publicKeyParameters))
                {
                    byte[] dh = ephemeral.DeriveRawSecretAgreement(recipientPub.PublicKey);

                    byte[] pkRm = new byte[Suite.EncapsulationKeySizeInBytes];
                    SerializePublicKey(_publicKeyParameters, pkRm);

                    byte[] kemContext = new byte[encapsulatedKey.Length + pkRm.Length];
                    encapsulatedKey.CopyTo(kemContext);
                    pkRm.CopyTo(kemContext.AsSpan(encapsulatedKey.Length));

                    byte[] sharedSecret = ExtractAndExpand(Suite, dh, kemContext);

                    byte mode = psk.IsEmpty ? (byte)0x00 : (byte)0x01;
                    return CreateSenderContext(Suite, sharedSecret, info, mode, psk, pskId);
                }
            }
        }

        protected override HpkeSenderContext SetupSenderAuthCore(
            Span<byte> encapsulatedKey,
            Hpke senderKey,
            ReadOnlySpan<byte> info)
        {
            return SetupSenderAuthPskCore(encapsulatedKey, senderKey, info, default, default);
        }

        protected override HpkeSenderContext SetupSenderAuthPskCore(
            Span<byte> encapsulatedKey,
            Hpke senderKey,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId)
        {
            bool disposeSenderPrivateKey = false;
            ECDiffieHellman senderPrivateKey;
            ECParameters senderPublicKeyParameters;
            byte[]? senderPrivateKeyBytes = null;
            byte[]? dh1 = null;
            byte[]? dh2 = null;
            byte[]? dh = null;
            byte[]? sharedSecret = null;

            if (senderKey is HpkeManaged senderManaged)
            {
                senderPrivateKey = senderManaged.GetPrivateKey();
                senderPublicKeyParameters = senderManaged.GetPublicKeyParameters();
            }
            else
            {
                senderPrivateKeyBytes = senderKey.ExportDecapsulationKey();
                senderPrivateKey = ECDiffieHellman.Create(new ECParameters
                {
                    Curve = GetCurve(Suite),
                    D = senderPrivateKeyBytes,
                });
                senderPublicKeyParameters = ExportPublicKeyParameters(senderKey, Suite);
                disposeSenderPrivateKey = true;
            }

            try
            {
                ECCurve curve = GetCurve(Suite);
                using (ECDiffieHellman ephemeral = ECDiffieHellman.Create(curve))
                {
                    ECParameters ephPub = ephemeral.ExportParameters(includePrivateParameters: false);
                    SerializePublicKey(ephPub, encapsulatedKey);

                    using (ECDiffieHellman recipientPub = ECDiffieHellman.Create(_publicKeyParameters))
                    {
                        dh1 = ephemeral.DeriveRawSecretAgreement(recipientPub.PublicKey);
                        dh2 = senderPrivateKey.DeriveRawSecretAgreement(recipientPub.PublicKey);
                        dh = new byte[dh1.Length + dh2.Length];
                        dh1.CopyTo(dh, 0);
                        dh2.CopyTo(dh, dh1.Length);

                        byte[] pkRm = new byte[Suite.EncapsulationKeySizeInBytes];
                        SerializePublicKey(_publicKeyParameters, pkRm);

                        byte[] pkSm = new byte[Suite.EncapsulationKeySizeInBytes];
                        SerializePublicKey(senderPublicKeyParameters, pkSm);

                        byte[] kemContext = new byte[encapsulatedKey.Length + pkRm.Length + pkSm.Length];
                        encapsulatedKey.CopyTo(kemContext);
                        pkRm.CopyTo(kemContext.AsSpan(encapsulatedKey.Length));
                        pkSm.CopyTo(kemContext.AsSpan(encapsulatedKey.Length + pkRm.Length));

                        sharedSecret = ExtractAndExpand(Suite, dh, kemContext);

                        byte mode = psk.IsEmpty ? (byte)0x02 : (byte)0x03;
                        return CreateSenderContext(Suite, sharedSecret, info, mode, psk, pskId);
                    }
                }
            }
            finally
            {
                if (disposeSenderPrivateKey)
                {
                    senderPrivateKey.Dispose();
                }

                ZeroMemory(senderPrivateKeyBytes);
                ZeroMemory(dh1);
                ZeroMemory(dh2);
                ZeroMemory(dh);
                ZeroMemory(sharedSecret);
            }
        }

        protected override HpkeReceiverContext SetupReceiverCore(
            ReadOnlySpan<byte> encapsulatedKey,
            ReadOnlySpan<byte> info)
        {
            return SetupReceiverPskCore(encapsulatedKey, info, default, default);
        }

        protected override HpkeReceiverContext SetupReceiverPskCore(
            ReadOnlySpan<byte> encapsulatedKey,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId)
        {
            ECDiffieHellman privateKey = GetPrivateKey();

            ECParameters ephPub = DeserializePublicKey(Suite, encapsulatedKey);
            using (ECDiffieHellman ephPublicKey = ECDiffieHellman.Create(ephPub))
            {
                byte[] dh = privateKey.DeriveRawSecretAgreement(ephPublicKey.PublicKey);

                byte[] pkRm = new byte[Suite.EncapsulationKeySizeInBytes];
                SerializePublicKey(_publicKeyParameters, pkRm);

                byte[] kemContext = new byte[encapsulatedKey.Length + pkRm.Length];
                encapsulatedKey.CopyTo(kemContext);
                pkRm.CopyTo(kemContext.AsSpan(encapsulatedKey.Length));

                byte[] sharedSecret = ExtractAndExpand(Suite, dh, kemContext);

                byte mode = psk.IsEmpty ? (byte)0x00 : (byte)0x01;
                return CreateReceiverContext(Suite, sharedSecret, info, mode, psk, pskId);
            }
        }

        protected override HpkeReceiverContext SetupReceiverAuthCore(
            ReadOnlySpan<byte> encapsulatedKey,
            Hpke senderKey,
            ReadOnlySpan<byte> info)
        {
            return SetupReceiverAuthPskCore(encapsulatedKey, senderKey, info, default, default);
        }

        protected override HpkeReceiverContext SetupReceiverAuthPskCore(
            ReadOnlySpan<byte> encapsulatedKey,
            Hpke senderKey,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> psk,
            ReadOnlySpan<byte> pskId)
        {
            ECDiffieHellman privateKey = GetPrivateKey();
            ECParameters senderPublicKeyParameters = ExportPublicKeyParameters(senderKey, Suite);
            byte[]? dh1 = null;
            byte[]? dh2 = null;
            byte[]? dh = null;
            byte[]? sharedSecret = null;

            try
            {
                ECParameters ephPub = DeserializePublicKey(Suite, encapsulatedKey);
                using (ECDiffieHellman ephPublicKey = ECDiffieHellman.Create(ephPub))
                using (ECDiffieHellman senderPublicKey = ECDiffieHellman.Create(senderPublicKeyParameters))
                {
                    dh1 = privateKey.DeriveRawSecretAgreement(ephPublicKey.PublicKey);
                    dh2 = privateKey.DeriveRawSecretAgreement(senderPublicKey.PublicKey);
                    dh = new byte[dh1.Length + dh2.Length];
                    dh1.CopyTo(dh, 0);
                    dh2.CopyTo(dh, dh1.Length);

                    byte[] pkRm = new byte[Suite.EncapsulationKeySizeInBytes];
                    SerializePublicKey(_publicKeyParameters, pkRm);

                    byte[] pkSm = new byte[Suite.EncapsulationKeySizeInBytes];
                    SerializePublicKey(senderPublicKeyParameters, pkSm);

                    byte[] kemContext = new byte[encapsulatedKey.Length + pkRm.Length + pkSm.Length];
                    encapsulatedKey.CopyTo(kemContext);
                    pkRm.CopyTo(kemContext.AsSpan(encapsulatedKey.Length));
                    pkSm.CopyTo(kemContext.AsSpan(encapsulatedKey.Length + pkRm.Length));

                    sharedSecret = ExtractAndExpand(Suite, dh, kemContext);

                    byte mode = psk.IsEmpty ? (byte)0x02 : (byte)0x03;
                    return CreateReceiverContext(Suite, sharedSecret, info, mode, psk, pskId);
                }
            }
            finally
            {
                ZeroMemory(dh1);
                ZeroMemory(dh2);
                ZeroMemory(dh);
                ZeroMemory(sharedSecret);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _privateKey?.Dispose();
            }

            base.Dispose(disposing);
        }

        // ----------------------------------------------------------------
        // DHKEM helpers
        // ----------------------------------------------------------------

        private static ECCurve GetCurve(HpkeSuite suite) =>
            suite.KemAlgorithm switch
            {
                HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256 => ECCurve.NamedCurves.nistP256,
                HpkeSuite.Kem.DHKEM_P384_HKDF_SHA384 => ECCurve.NamedCurves.nistP384,
                _ => throw new CryptographicException(SR.Cryptography_CurveNotSupported),
            };

        private static HashAlgorithmName GetKemHash(HpkeSuite suite) =>
            suite.KemAlgorithm switch
            {
                HpkeSuite.Kem.DHKEM_P256_HKDF_SHA256 => HashAlgorithmName.SHA256,
                HpkeSuite.Kem.DHKEM_P384_HKDF_SHA384 => HashAlgorithmName.SHA384,
                _ => throw new CryptographicException(),
            };

        private static HashAlgorithmName GetKdfHash(HpkeSuite suite) =>
            suite.KdfAlgorithm switch
            {
                HpkeSuite.Kdf.HKDF_SHA256 => HashAlgorithmName.SHA256,
                HpkeSuite.Kdf.HKDF_SHA384 => HashAlgorithmName.SHA384,
                HpkeSuite.Kdf.HKDF_SHA512 => HashAlgorithmName.SHA512,
                _ => throw new CryptographicException(),
            };

        private static int GetHashLength(HashAlgorithmName hash)
        {
            if (hash == HashAlgorithmName.SHA256)
                return 32;
            if (hash == HashAlgorithmName.SHA384)
                return 48;
            if (hash == HashAlgorithmName.SHA512)
                return 64;

            throw new CryptographicException();
        }

        private static void SerializePublicKey(ECParameters parameters, Span<byte> destination)
        {
            // Uncompressed point: 0x04 || X || Y
            Debug.Assert(parameters.Q.X is not null && parameters.Q.Y is not null);

            destination[0] = 0x04;
            parameters.Q.X.CopyTo(destination.Slice(1));
            parameters.Q.Y.CopyTo(destination.Slice(1 + parameters.Q.X.Length));
        }

        private static ECParameters DeserializePublicKey(HpkeSuite suite, ReadOnlySpan<byte> source)
        {
            if (source[0] != 0x04)
            {
                throw new CryptographicException();
            }

            int coordinateSize = (suite.EncapsulationKeySizeInBytes - 1) / 2;

            return new ECParameters
            {
                Curve = GetCurve(suite),
                Q = new ECPoint
                {
                    X = source.Slice(1, coordinateSize).ToArray(),
                    Y = source.Slice(1 + coordinateSize, coordinateSize).ToArray(),
                },
            };
        }

        // ----------------------------------------------------------------
        // LabeledExtract / LabeledExpand with KEM suite_id
        // ----------------------------------------------------------------

        private static byte[] BuildKemSuiteId(HpkeSuite suite)
        {
            // suite_id = "KEM" || I2OSP(kem_id, 2)
            byte[] suiteId = new byte[5];
            suiteId[0] = (byte)'K';
            suiteId[1] = (byte)'E';
            suiteId[2] = (byte)'M';
            BinaryPrimitives.WriteUInt16BigEndian(suiteId.AsSpan(3), suite.KemId);

            return suiteId;
        }

        private static byte[] BuildHpkeSuiteId(HpkeSuite suite)
        {
            // suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
            byte[] suiteId = new byte[10];
            suiteId[0] = (byte)'H';
            suiteId[1] = (byte)'P';
            suiteId[2] = (byte)'K';
            suiteId[3] = (byte)'E';
            BinaryPrimitives.WriteUInt16BigEndian(suiteId.AsSpan(4), suite.KemId);
            BinaryPrimitives.WriteUInt16BigEndian(suiteId.AsSpan(6), suite.KdfId);
            BinaryPrimitives.WriteUInt16BigEndian(suiteId.AsSpan(8), suite.AeadId);

            return suiteId;
        }

        private static readonly byte[] s_hpkeV1 = "HPKE-v1"u8.ToArray();

        private static byte[] LabeledExtract(
            HashAlgorithmName hash,
            byte[] suiteId,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> label,
            ReadOnlySpan<byte> ikm)
        {
            // labeled_ikm = "HPKE-v1" || suite_id || label || ikm
            byte[] labeledIkm = new byte[s_hpkeV1.Length + suiteId.Length + label.Length + ikm.Length];
            int offset = 0;
            s_hpkeV1.CopyTo(labeledIkm, 0);
            offset += s_hpkeV1.Length;
            suiteId.CopyTo(labeledIkm.AsSpan(offset));
            offset += suiteId.Length;
            label.CopyTo(labeledIkm.AsSpan(offset));
            offset += label.Length;
            ikm.CopyTo(labeledIkm.AsSpan(offset));

            int hashLen = GetHashLength(hash);
            byte[] prk = new byte[hashLen];
            HKDF.Extract(hash, labeledIkm, salt, prk);

            return prk;
        }

        private static byte[] LabeledExpand(
            HashAlgorithmName hash,
            byte[] suiteId,
            ReadOnlySpan<byte> prk,
            ReadOnlySpan<byte> label,
            ReadOnlySpan<byte> info,
            int length)
        {
            // labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
            byte[] labeledInfo = new byte[2 + s_hpkeV1.Length + suiteId.Length + label.Length + info.Length];
            BinaryPrimitives.WriteUInt16BigEndian(labeledInfo, (ushort)length);
            int offset = 2;
            s_hpkeV1.CopyTo(labeledInfo.AsSpan(offset));
            offset += s_hpkeV1.Length;
            suiteId.CopyTo(labeledInfo.AsSpan(offset));
            offset += suiteId.Length;
            label.CopyTo(labeledInfo.AsSpan(offset));
            offset += label.Length;
            info.CopyTo(labeledInfo.AsSpan(offset));

            byte[] output = new byte[length];
            HKDF.Expand(hash, prk, output, labeledInfo);

            return output;
        }

        // ----------------------------------------------------------------
        // ExtractAndExpand (DHKEM)
        // ----------------------------------------------------------------

        private static byte[] ExtractAndExpand(HpkeSuite suite, byte[] dh, byte[] kemContext)
        {
            HashAlgorithmName kemHash = GetKemHash(suite);
            byte[] kemSuiteId = BuildKemSuiteId(suite);
            int nSecret = GetHashLength(kemHash);

            byte[] eaePrk = LabeledExtract(kemHash, kemSuiteId, ReadOnlySpan<byte>.Empty, "eae_prk"u8, dh);
            byte[] sharedSecret = LabeledExpand(kemHash, kemSuiteId, eaePrk, "shared_secret"u8, kemContext, nSecret);

            return sharedSecret;
        }

        private static void ZeroMemory(byte[]? buffer)
        {
            if (buffer is not null)
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }

        // ----------------------------------------------------------------
        // KeySchedule
        // ----------------------------------------------------------------

        private static (byte[] Key, byte[] BaseNonce, byte[] ExporterSecret) KeySchedule(
            HpkeSuite suite,
            byte[] sharedSecret,
            ReadOnlySpan<byte> info,
            byte mode = 0x00,
            ReadOnlySpan<byte> psk = default,
            ReadOnlySpan<byte> pskId = default)
        {
            HashAlgorithmName kdfHash = GetKdfHash(suite);
            byte[] hpkeSuiteId = BuildHpkeSuiteId(suite);
            int nh = GetHashLength(kdfHash);

            // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
            byte[] pskIdHash = LabeledExtract(kdfHash, hpkeSuiteId, ReadOnlySpan<byte>.Empty, "psk_id_hash"u8, pskId);

            // info_hash = LabeledExtract("", "info_hash", info)
            byte[] infoHash = LabeledExtract(kdfHash, hpkeSuiteId, ReadOnlySpan<byte>.Empty, "info_hash"u8, info);

            // key_schedule_context = mode || psk_id_hash || info_hash
            byte[] ksCtx = new byte[1 + pskIdHash.Length + infoHash.Length];
            ksCtx[0] = mode;
            pskIdHash.CopyTo(ksCtx.AsSpan(1));
            infoHash.CopyTo(ksCtx.AsSpan(1 + pskIdHash.Length));

            // secret = LabeledExtract(shared_secret, "secret", psk)
            byte[] secret = LabeledExtract(kdfHash, hpkeSuiteId, sharedSecret, "secret"u8, psk);

            // key = LabeledExpand(secret, "key", key_schedule_context, Nk)
            byte[] key = LabeledExpand(kdfHash, hpkeSuiteId, secret, "key"u8, ksCtx, suite.AeadKeySizeInBytes);

            // base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
            byte[] baseNonce = LabeledExpand(kdfHash, hpkeSuiteId, secret, "base_nonce"u8, ksCtx, suite.AeadNonceSizeInBytes);

            // exporter_secret = LabeledExpand(secret, "exp", key_schedule_context, Nh)
            byte[] exporterSecret = LabeledExpand(kdfHash, hpkeSuiteId, secret, "exp"u8, ksCtx, nh);

            return (key, baseNonce, exporterSecret);
        }

        // ----------------------------------------------------------------
        // Single-shot Seal / Open using KeySchedule at seq=0
        // ----------------------------------------------------------------

        private static void DeriveKeyScheduleAndSeal(
            HpkeSuite suite,
            byte[] sharedSecret,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> aad)
        {
            (byte[] key, byte[] baseNonce, _) = KeySchedule(suite, sharedSecret, info);

            // seq=0, so nonce = base_nonce XOR I2OSP(0, Nn) = base_nonce
            AeadSeal(suite, key, baseNonce, plaintext, ciphertext, aad);
        }

        private static void DeriveKeyScheduleAndOpen(
            HpkeSuite suite,
            byte[] sharedSecret,
            ReadOnlySpan<byte> info,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> aad)
        {
            (byte[] key, byte[] baseNonce, _) = KeySchedule(suite, sharedSecret, info);

            AeadOpen(suite, key, baseNonce, ciphertext, plaintext, aad);
        }

        // ----------------------------------------------------------------
        // AEAD helpers
        // ----------------------------------------------------------------

        private static void AeadSeal(
            HpkeSuite suite,
            byte[] key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertextWithTag,
            ReadOnlySpan<byte> aad)
        {
            Span<byte> ciphertext = ciphertextWithTag.Slice(0, plaintext.Length);
            Span<byte> tag = ciphertextWithTag.Slice(plaintext.Length);

            switch (suite.AeadAlgorithm)
            {
                case HpkeSuite.Aead.Aes128Gcm:
                case HpkeSuite.Aead.Aes256Gcm:
#pragma warning disable CA1416
                    using (AesGcm aesGcm = new AesGcm(key, suite.AeadTagSizeInBytes))
                    {
                        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                    }
                    break;

                case HpkeSuite.Aead.ChaCha20Poly1305:
                    using (ChaCha20Poly1305 chacha = new ChaCha20Poly1305(key))
                    {
                        chacha.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                    }
                    break;
#pragma warning restore CA1416

                default:
                    throw new CryptographicException();
            }
        }

        private static void AeadOpen(
            HpkeSuite suite,
            byte[] key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertextWithTag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> aad)
        {
            ReadOnlySpan<byte> ciphertext = ciphertextWithTag.Slice(0, plaintext.Length);
            ReadOnlySpan<byte> tag = ciphertextWithTag.Slice(plaintext.Length);

            switch (suite.AeadAlgorithm)
            {
                case HpkeSuite.Aead.Aes128Gcm:
                case HpkeSuite.Aead.Aes256Gcm:
#pragma warning disable CA1416
                    using (AesGcm aesGcm = new AesGcm(key, suite.AeadTagSizeInBytes))
                    {
                        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                    }
                    break;

                case HpkeSuite.Aead.ChaCha20Poly1305:
                    using (ChaCha20Poly1305 chacha = new ChaCha20Poly1305(key))
                    {
                        chacha.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                    }
                    break;
#pragma warning restore CA1416

                default:
                    throw new CryptographicException();
            }
        }

        // ----------------------------------------------------------------
        // Nonce computation: xor(base_nonce, I2OSP(seq, Nn))
        // ----------------------------------------------------------------

        private static unsafe byte[] ComputeNonce(byte[] baseNonce, long seq)
        {
            byte[] nonce = new byte[baseNonce.Length];
            baseNonce.CopyTo(nonce.AsSpan());

            // XOR the sequence number (big-endian) into the rightmost bytes
            Span<byte> seqBytes = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(seqBytes, seq);

            int seqOffset = seqBytes.Length - nonce.Length;

            for (int i = 0; i < nonce.Length; i++)
            {
                int seqIdx = i + seqOffset;

                if (seqIdx >= 0)
                {
                    nonce[i] ^= seqBytes[seqIdx];
                }
            }

            return nonce;
        }

        // ----------------------------------------------------------------
        // Context creation
        // ----------------------------------------------------------------

        private static HpkeManagedSenderContext CreateSenderContext(
            HpkeSuite suite,
            byte[] sharedSecret,
            ReadOnlySpan<byte> info,
            byte mode = 0x00,
            ReadOnlySpan<byte> psk = default,
            ReadOnlySpan<byte> pskId = default)
        {
            (byte[] key, byte[] baseNonce, byte[] exporterSecret) = KeySchedule(suite, sharedSecret, info, mode, psk, pskId);

            return new HpkeManagedSenderContext(suite, key, baseNonce, exporterSecret);
        }

        private static HpkeManagedReceiverContext CreateReceiverContext(
            HpkeSuite suite,
            byte[] sharedSecret,
            ReadOnlySpan<byte> info,
            byte mode = 0x00,
            ReadOnlySpan<byte> psk = default,
            ReadOnlySpan<byte> pskId = default)
        {
            (byte[] key, byte[] baseNonce, byte[] exporterSecret) = KeySchedule(suite, sharedSecret, info, mode, psk, pskId);

            return new HpkeManagedReceiverContext(suite, key, baseNonce, exporterSecret);
        }

        // ----------------------------------------------------------------
        // Sender context
        // ----------------------------------------------------------------

        private sealed class HpkeManagedSenderContext : HpkeSenderContext
        {
            private readonly HpkeSuite _suite;
            private readonly byte[] _key;
            private readonly byte[] _baseNonce;
            private readonly byte[] _exporterSecret;
            private long _seq;

            internal HpkeManagedSenderContext(HpkeSuite suite, byte[] key, byte[] baseNonce, byte[] exporterSecret)
            {
                _suite = suite;
                _key = key;
                _baseNonce = baseNonce;
                _exporterSecret = exporterSecret;
            }

            protected override void SealCore(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> aad)
            {
                long maxSeq = (1L << (8 * _baseNonce.Length)) - 1;

                if (_seq >= maxSeq)
                {
                    throw new CryptographicException();
                }

                byte[] nonce = ComputeNonce(_baseNonce, _seq);
                AeadSeal(_suite, _key, nonce, plaintext, ciphertext, aad);
                _seq++;
            }

            protected override void ExportCore(ReadOnlySpan<byte> exporterContext, Span<byte> destination)
            {
                byte[] hpkeSuiteId = BuildHpkeSuiteId(_suite);
                HashAlgorithmName kdfHash = GetKdfHash(_suite);
                byte[] result = LabeledExpand(kdfHash, hpkeSuiteId, _exporterSecret, "sec"u8, exporterContext, destination.Length);
                result.CopyTo(destination);
            }

            protected override int GetAeadTagSizeInBytes() => _suite.AeadTagSizeInBytes;

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    CryptographicOperations.ZeroMemory(_key);
                    CryptographicOperations.ZeroMemory(_baseNonce);
                    CryptographicOperations.ZeroMemory(_exporterSecret);
                }

                base.Dispose(disposing);
            }
        }

        // ----------------------------------------------------------------
        // Receiver context
        // ----------------------------------------------------------------

        private sealed class HpkeManagedReceiverContext : HpkeReceiverContext
        {
            private readonly HpkeSuite _suite;
            private readonly byte[] _key;
            private readonly byte[] _baseNonce;
            private readonly byte[] _exporterSecret;
            private long _seq;

            internal HpkeManagedReceiverContext(HpkeSuite suite, byte[] key, byte[] baseNonce, byte[] exporterSecret)
            {
                _suite = suite;
                _key = key;
                _baseNonce = baseNonce;
                _exporterSecret = exporterSecret;
            }

            protected override void OpenCore(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> aad)
            {
                long maxSeq = (1L << (8 * _baseNonce.Length)) - 1;

                if (_seq >= maxSeq)
                {
                    throw new CryptographicException();
                }

                byte[] nonce = ComputeNonce(_baseNonce, _seq);
                AeadOpen(_suite, _key, nonce, ciphertext, plaintext, aad);
                _seq++;
            }

            protected override void ExportCore(ReadOnlySpan<byte> exporterContext, Span<byte> destination)
            {
                byte[] hpkeSuiteId = BuildHpkeSuiteId(_suite);
                HashAlgorithmName kdfHash = GetKdfHash(_suite);
                byte[] result = LabeledExpand(kdfHash, hpkeSuiteId, _exporterSecret, "sec"u8, exporterContext, destination.Length);
                result.CopyTo(destination);
            }

            protected override int GetAeadTagSizeInBytes() => _suite.AeadTagSizeInBytes;

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    CryptographicOperations.ZeroMemory(_key);
                    CryptographicOperations.ZeroMemory(_baseNonce);
                    CryptographicOperations.ZeroMemory(_exporterSecret);
                }

                base.Dispose(disposing);
            }
        }
    }
}
