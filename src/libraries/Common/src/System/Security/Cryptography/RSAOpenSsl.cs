// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable
using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using Microsoft.Win32.SafeHandles;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    public partial class RSA : AsymmetricAlgorithm
    {
        public static new RSA Create() => new RSAImplementation.RSAOpenSsl();
    }

    internal static partial class RSAImplementation
    {
#endif
    public sealed partial class RSAOpenSsl : RSA
    {
        private const int BitsPerByte = 8;

        // 65537 (0x10001) in big-endian form
        private static ReadOnlySpan<byte> DefaultExponent => new byte[] { 0x01, 0x00, 0x01 };

        private Lazy<SafeEvpPKeyHandle> _key;

        public RSAOpenSsl()
            : this(2048)
        {
        }

        public RSAOpenSsl(int keySize)
        {
            base.KeySize = keySize;
            _key = new Lazy<SafeEvpPKeyHandle>(GenerateKey);
        }

        public override int KeySize
        {
            set
            {
                if (KeySize == value)
                {
                    return;
                }

                // Set the KeySize before FreeKey so that an invalid value doesn't throw away the key
                base.KeySize = value;

                ThrowIfDisposed();
                FreeKey();
                _key = new Lazy<SafeEvpPKeyHandle>(GenerateKey);
            }
        }

        private void ForceSetKeySize(int newKeySize)
        {
            // In the event that a key was loaded via ImportParameters or an IntPtr/SafeHandle
            // it could be outside of the bounds that we currently represent as "legal key sizes".
            // Since that is our view into the underlying component it can be detached from the
            // component's understanding.  If it said it has opened a key, and this is the size, trust it.
            KeySizeValue = newKeySize;
        }

        public override KeySizes[] LegalKeySizes
        {
            get
            {
                // While OpenSSL 1.0.x and 1.1.0 will generate RSA-384 keys,
                // OpenSSL 1.1.1 has lifted the minimum to RSA-512.
                //
                // Rather than make the matrix even more complicated,
                // the low limit now is 512 on all OpenSSL-based RSA.
                return new[] { new KeySizes(512, 16384, 8) };
            }
        }

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            ValidatePadding(padding);

            SafeEvpPKeyHandle key = GetKey();
            int rsaSize = AsymmetricAlgorithmHelpers.BitsToBytes(KeySize);
            byte[]? buf = null;
            Span<byte> destination = default;

            try
            {
                buf = CryptoPool.Rent(rsaSize);
                destination = new Span<byte>(buf, 0, rsaSize);

                if (!TryDecrypt(key, data, destination, padding, out int bytesWritten))
                {
                    Debug.Fail($"{nameof(TryDecrypt)} should not return false for RSA_size buffer");
                    throw new CryptographicException();
                }

                return destination.Slice(0, bytesWritten).ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(destination);
                CryptoPool.Return(buf!, clearSize: 0);
            }
        }

        public override bool TryDecrypt(
            ReadOnlySpan<byte> data,
            Span<byte> destination,
            RSAEncryptionPadding padding,
            out int bytesWritten)
        {
            ValidatePadding(padding);

            SafeEvpPKeyHandle key = GetKey();
            int keySizeBytes = AsymmetricAlgorithmHelpers.BitsToBytes(KeySize);

            // OpenSSL does not take a length value for the destination, so it can write out of bounds.
            // To prevent the OOB write, decrypt into a temporary buffer.
            if (destination.Length < keySizeBytes)
            {
                Span<byte> tmp = stackalloc byte[512];
                byte[]? rent = null;

                // RSA up through 4096 stackalloc
                if (keySizeBytes > tmp.Length)
                {
                    rent = ArrayPool<byte>.Shared.Rent(keySizeBytes);
                    tmp = rent;
                }

                bool ret = TryDecrypt(key, data, tmp, padding, out bytesWritten);

                if (ret)
                {
                    tmp = tmp.Slice(0, bytesWritten);

                    if (bytesWritten > destination.Length)
                    {
                        ret = false;
                        bytesWritten = 0;
                    }
                    else
                    {
                        tmp.CopyTo(destination);
                    }

                    CryptographicOperations.ZeroMemory(tmp.Slice(0, bytesWritten));
                }

                if (rent != null)
                {
                    // Already cleared
                    ArrayPool<byte>.Shared.Return(rent);
                }

                return ret;
            }

            return TryDecrypt(key, data, destination, padding, out bytesWritten);
        }

        private static bool TryDecrypt(
            SafeEvpPKeyHandle key,
            ReadOnlySpan<byte> data,
            Span<byte> destination,
            RSAEncryptionPadding rsaPadding,
            out int bytesWritten)
        {
            // Caller should have already checked this.
            Debug.Assert(!key.IsInvalid);

            // No destination size check here, it's the caller's responsibility.
            IntPtr hashAlgorithm = IntPtr.Zero;

            if (rsaPadding.Mode == RSAEncryptionPaddingMode.Oaep)
            {
                Debug.Assert(rsaPadding.OaepHashAlgorithm.Name != null);
                hashAlgorithm = Interop.Crypto.GetDigestAlgorithm(rsaPadding.OaepHashAlgorithm.Name);
            }

            int returnValue = Interop.Crypto.RsaDecrypt(
                key,
                data,
                rsaPadding.Mode,
                hashAlgorithm,
                destination);

            // -1 is an OpenSSL error (exception)
            // -2 is a usage error (assert)
            // -3 is that the data to decrypt was not exactly the right size

            if (returnValue == -3)
            {
                throw new CryptographicException(SR.Cryptography_RSA_DecryptWrongSize);
            }

            if (returnValue < 0)
            {
                Debug.Assert(returnValue == -1);
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }

            bytesWritten = returnValue;
            return true;
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            ValidatePadding(padding);

            SafeEvpPKeyHandle key = GetKey();
            byte[] buf = new byte[AsymmetricAlgorithmHelpers.BitsToBytes(KeySize)];

            bool encrypted = TryEncrypt(
                key,
                data,
                buf,
                padding,
                out int bytesWritten);

            if (!encrypted || bytesWritten != buf.Length)
            {
                Debug.Fail($"TryEncrypt behaved unexpectedly: {nameof(encrypted)}=={encrypted}, {nameof(bytesWritten)}=={bytesWritten}, {nameof(buf.Length)}=={buf.Length}");
                throw new CryptographicException();
            }

            return buf;
        }

        public override bool TryEncrypt(ReadOnlySpan<byte> data, Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten)
        {
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            ValidatePadding(padding);

            SafeEvpPKeyHandle key = GetKey();
            int rsaSize = AsymmetricAlgorithmHelpers.BitsToBytes(KeySize);

            if (destination.Length < rsaSize)
            {
                bytesWritten = 0;
                return false;
            }

            bool ret = TryEncrypt(key, data, destination, padding, out bytesWritten);
            Debug.Assert(!ret || bytesWritten == rsaSize);
            return ret;
        }

        private static bool TryEncrypt(
            SafeEvpPKeyHandle key,
            ReadOnlySpan<byte> data,
            Span<byte> destination,
            RSAEncryptionPadding padding,
            out int bytesWritten)
        {
            // Caller should have already checked this.
            Debug.Assert(!key.IsInvalid);

            // No destination size check here, it's the caller's responsibility.
            IntPtr hashAlgorithm = IntPtr.Zero;

            if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            {
                Debug.Assert(padding.OaepHashAlgorithm.Name != null);
                hashAlgorithm = Interop.Crypto.GetDigestAlgorithm(padding.OaepHashAlgorithm.Name);
            }

            int returnValue = Interop.Crypto.RsaEncrypt(
                key,
                data,
                padding.Mode,
                hashAlgorithm,
                destination);

            if (returnValue < 0)
            {
                Debug.Assert(returnValue == -1);
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }

            bytesWritten = returnValue;
            return true;
        }

        private static Interop.Crypto.RsaPadding GetInteropPadding(
            RSAEncryptionPadding padding,
            out RsaPaddingProcessor? rsaPaddingProcessor)
        {
            if (padding == RSAEncryptionPadding.Pkcs1)
            {
                rsaPaddingProcessor = null;
                return Interop.Crypto.RsaPadding.Pkcs1;
            }

            if (padding == RSAEncryptionPadding.OaepSHA1)
            {
                rsaPaddingProcessor = null;
                return Interop.Crypto.RsaPadding.OaepSHA1;
            }

            if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            {
                rsaPaddingProcessor = RsaPaddingProcessor.OpenProcessor(padding.OaepHashAlgorithm);
                return Interop.Crypto.RsaPadding.NoPadding;
            }

            throw PaddingModeNotSupported();
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            RSAParameters rsaParameters = default;
            ArraySegment<byte> rented = default;

            try
            {
                if (includePrivateParameters)
                {
                    rented = NativeExportRSAPrivateKey();
                    AsymmetricAlgorithmHelpers.FromRSAPrivateKey(rented, ref rsaParameters);
                }
                else
                {
                    rented = NativeExportRSAPublicKey();
                    AsymmetricAlgorithmHelpers.FromRSAPublicKey(rented, ref rsaParameters);
                }
            }
            finally
            {
                if (rented.Array != null)
                {
                    CryptoPool.Return(rented);
                    rented = default;
                }
            }

            return rsaParameters;
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            ValidateParameters(ref parameters);
            ThrowIfDisposed();

            SafeRsaHandle key = Interop.Crypto.RsaCreate();
            bool imported = false;

            Interop.Crypto.CheckValidOpenSslHandle(key);

            try
            {
                if (!Interop.Crypto.SetRsaParameters(
                    key,
                    parameters.Modulus,
                    parameters.Modulus != null ? parameters.Modulus.Length : 0,
                    parameters.Exponent,
                    parameters.Exponent != null ? parameters.Exponent.Length : 0,
                    parameters.D,
                    parameters.D != null ? parameters.D.Length : 0,
                    parameters.P,
                    parameters.P != null ? parameters.P.Length : 0,
                    parameters.DP,
                    parameters.DP != null ? parameters.DP.Length : 0,
                    parameters.Q,
                    parameters.Q != null ? parameters.Q.Length : 0,
                    parameters.DQ,
                    parameters.DQ != null ? parameters.DQ.Length : 0,
                    parameters.InverseQ,
                    parameters.InverseQ != null ? parameters.InverseQ.Length : 0))
                {
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }

                imported = true;
            }
            finally
            {
                if (!imported)
                {
                    key.Dispose();
                }
            }

            SafeEvpPKeyHandle pkey = Interop.Crypto.EvpPkeyCreate();

            if (!Interop.Crypto.EvpPkeySetRsa(pkey, key))
            {
                pkey.Dispose();
                key.Dispose();
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }

            FreeKey();

            _key = new Lazy<SafeEvpPKeyHandle>(pkey);

            // Use ForceSet instead of the property setter to ensure that LegalKeySizes doesn't interfere
            // with the already loaded key.
            ForceSetKeySize(BitsPerByte * Interop.Crypto.RsaSize(key));
            key.Dispose();
        }

        public override void ImportRSAPublicKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            ThrowIfDisposed();

            int read;

            try
            {
                AsnDecoder.ReadEncodedValue(
                    source,
                    AsnEncodingRules.BER,
                    out _,
                    out _,
                    out read);
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }

            SafeRsaHandle key = Interop.Crypto.DecodeRsaPublicKey(source.Slice(0, read));

            Interop.Crypto.CheckValidOpenSslHandle(key);

            SafeEvpPKeyHandle pkey = Interop.Crypto.EvpPkeyCreate();

            if (!Interop.Crypto.EvpPkeySetRsa(pkey, key))
            {
                pkey.Dispose();
                key.Dispose();
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }

            FreeKey();
            _key = new Lazy<SafeEvpPKeyHandle>(pkey);

            // Use ForceSet instead of the property setter to ensure that LegalKeySizes doesn't interfere
            // with the already loaded key.
            ForceSetKeySize(BitsPerByte * Interop.Crypto.RsaSize(key));
            key.Dispose();

            bytesRead = read;
        }

        public override void ImportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            ThrowIfDisposed();
            base.ImportEncryptedPkcs8PrivateKey(passwordBytes, source, out bytesRead);
        }

        public override void ImportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            ThrowIfDisposed();
            base.ImportEncryptedPkcs8PrivateKey(password, source, out bytesRead);
        }

        public override bool TryExportRSAPublicKey(Span<byte> destination, out int bytesWritten)
        {
            SafeEvpPKeyHandle key = GetKey();

            using (SafeBioHandle bio = Interop.Crypto.ExportRSAPublicKey(key))
            {
                return Interop.Crypto.TryReadMemoryBio(bio, destination, out bytesWritten);
            }
        }

        public override byte[] ExportRSAPublicKey()
        {
            SafeEvpPKeyHandle key = GetKey();

            using (SafeBioHandle bio = Interop.Crypto.ExportRSAPublicKey(key))
            {
                return Interop.Crypto.ReadMemoryBio(bio);
            }
        }

        public override bool TryExportRSAPrivateKey(Span<byte> destination, out int bytesWritten)
        {
            SafeEvpPKeyHandle key = GetKey();

            using (SafeBioHandle bio = Interop.Crypto.ExportRSAPrivateKey(key))
            {
                return Interop.Crypto.TryReadMemoryBio(bio, destination, out bytesWritten);
            }
        }

        public override byte[] ExportRSAPrivateKey()
        {
            SafeEvpPKeyHandle key = GetKey();

            using (SafeBioHandle bio = Interop.Crypto.ExportRSAPrivateKey(key))
            {
                ArraySegment<byte> rented = Interop.Crypto.RentReadMemoryBio(bio);
                byte[] ret = CryptoPool.AllocateArray(rented.Count, pinned: true);
                rented.AsSpan().CopyTo(ret);
                CryptoPool.Return(rented);

                return ret;
            }
        }

        private ArraySegment<byte> NativeExportRSAPublicKey()
        {
            SafeEvpPKeyHandle key = GetKey();

            using (SafeBioHandle bio = Interop.Crypto.ExportRSAPublicKey(key))
            {
                return Interop.Crypto.RentReadMemoryBio(bio);
            }
        }

        private ArraySegment<byte> NativeExportRSAPrivateKey()
        {
            SafeEvpPKeyHandle key = GetKey();

            using (SafeBioHandle bio = Interop.Crypto.ExportRSAPrivateKey(key))
            {
                return Interop.Crypto.RentReadMemoryBio(bio);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                FreeKey();
                _key = null!;
            }

            base.Dispose(disposing);
        }

        private void FreeKey()
        {
            if (_key != null && _key.IsValueCreated)
            {
                SafeEvpPKeyHandle handle = _key.Value;
                handle?.Dispose();
            }
        }

        private static void ValidateParameters(ref RSAParameters parameters)
        {
            if (parameters.Modulus == null || parameters.Exponent == null)
                throw new CryptographicException(SR.Argument_InvalidValue);

            if (!HasConsistentPrivateKey(ref parameters))
                throw new CryptographicException(SR.Argument_InvalidValue);
        }

        private static bool HasConsistentPrivateKey(ref RSAParameters parameters)
        {
            if (parameters.D == null)
            {
                if (parameters.P != null ||
                    parameters.DP != null ||
                    parameters.Q != null ||
                    parameters.DQ != null ||
                    parameters.InverseQ != null)
                {
                    return false;
                }
            }
            else
            {
                if (parameters.P == null ||
                    parameters.DP == null ||
                    parameters.Q == null ||
                    parameters.DQ == null ||
                    parameters.InverseQ == null)
                {
                    return false;
                }
            }

            return true;
        }

        private void ThrowIfDisposed()
        {
            if (_key == null)
            {
                throw new ObjectDisposedException(
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
                    nameof(RSA)
#else
                    nameof(RSAOpenSsl)
#endif
                );
            }
        }

        private SafeEvpPKeyHandle GetKey()
        {
            ThrowIfDisposed();

            SafeEvpPKeyHandle key = _key.Value;

            if (key == null || key.IsInvalid)
            {
                throw new CryptographicException(SR.Cryptography_OpenInvalidHandle);
            }

            return key;
        }

        private static void CheckReturn(int returnValue)
        {
            if (returnValue == -1)
            {
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }
        }

        private SafeEvpPKeyHandle GenerateKey()
        {
            return Interop.Crypto.RsaGenerateKey(KeySize);
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm) =>
            AsymmetricAlgorithmHelpers.HashData(data, offset, count, hashAlgorithm);

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm) =>
            AsymmetricAlgorithmHelpers.HashData(data, hashAlgorithm);

        protected override bool TryHashData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) =>
            AsymmetricAlgorithmHelpers.TryHashData(data, destination, hashAlgorithm, out bytesWritten);

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (hash == null)
                throw new ArgumentNullException(nameof(hash));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw HashAlgorithmNameNullOrEmpty();
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            if (!TrySignHash(
                hash,
                Span<byte>.Empty,
                hashAlgorithm, padding,
                true,
                out int bytesWritten,
                out byte[]? signature))
            {
                Debug.Fail("TrySignHash should not return false in allocation mode");
                throw new CryptographicException();
            }

            Debug.Assert(signature != null);
            return signature;
        }

        public override bool TrySignHash(
            ReadOnlySpan<byte> hash,
            Span<byte> destination,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding,
            out int bytesWritten)
        {
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw HashAlgorithmNameNullOrEmpty();
            }
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            bool ret = TrySignHash(
                hash,
                destination,
                hashAlgorithm,
                padding,
                false,
                out bytesWritten,
                out byte[]? alloced);

            Debug.Assert(alloced == null);
            return ret;
        }

        private bool TrySignHash(
            ReadOnlySpan<byte> hash,
            Span<byte> destination,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding,
            bool allocateSignature,
            out int bytesWritten,
            out byte[]? signature)
        {
            Debug.Assert(!string.IsNullOrEmpty(hashAlgorithm.Name));
            Debug.Assert(padding != null);

            signature = null;

            switch (padding.Mode)
            {
                case RSASignaturePaddingMode.Pkcs1:
                case RSASignaturePaddingMode.Pss:
                    break;
                default:
                    throw PaddingModeNotSupported();
            }

            SafeEvpPKeyHandle key = GetKey();

            int bytesRequired = AsymmetricAlgorithmHelpers.BitsToBytes(KeySize);

            if (allocateSignature)
            {
                Debug.Assert(destination.Length == 0);
                signature = new byte[bytesRequired];
                destination = signature;
            }

            if (destination.Length < bytesRequired)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = Interop.Crypto.RsaSignHash(
                key,
                padding.Mode,
                Interop.Crypto.GetDigestAlgorithm(hashAlgorithm.Name),
                hash,
                destination);

            Debug.Assert(bytesWritten == bytesRequired);

            return true;
        }

        public override bool VerifyHash(
            byte[] hash,
            byte[] signature,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            return VerifyHash(new ReadOnlySpan<byte>(hash), new ReadOnlySpan<byte>(signature), hashAlgorithm, padding);
        }

        public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw HashAlgorithmNameNullOrEmpty();
            }
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            if (padding == RSASignaturePadding.Pkcs1)
            {
                int algorithmNid = GetAlgorithmNid(hashAlgorithm);
                SafeEvpPKeyHandle pkey = GetKey();

                using (SafeRsaHandle rsa = Interop.Crypto.EvpPkeyGetRsa(pkey))
                {
                    return Interop.Crypto.RsaVerify(algorithmNid, hash, signature, rsa);
                }
            }
            else if (padding == RSASignaturePadding.Pss)
            {
                RsaPaddingProcessor processor = RsaPaddingProcessor.OpenProcessor(hashAlgorithm);
                SafeEvpPKeyHandle pkey = GetKey();
                // Temporary blockless using, pending refactor.
                using SafeRsaHandle rsa = Interop.Crypto.EvpPkeyGetRsa(pkey);

                int requiredBytes = Interop.Crypto.RsaSize(rsa);

                if (signature.Length != requiredBytes)
                {
                    return false;
                }

                if (hash.Length != processor.HashLength)
                {
                    return false;
                }

                byte[] rented = CryptoPool.Rent(requiredBytes);
                Span<byte> unwrapped = new Span<byte>(rented, 0, requiredBytes);

                try
                {
                    int ret = Interop.Crypto.RsaVerificationPrimitive(signature, unwrapped, rsa);

                    CheckReturn(ret);

                    Debug.Assert(
                        ret == requiredBytes,
                        $"RSA_private_encrypt returned {ret} when {requiredBytes} was expected");

                    return processor.VerifyPss(hash, unwrapped, KeySize);
                }
                finally
                {
                    CryptoPool.Return(rented, requiredBytes);
                }
            }

            throw PaddingModeNotSupported();
        }

        private static int GetAlgorithmNid(HashAlgorithmName hashAlgorithmName)
        {
            // All of the current HashAlgorithmName values correspond to the SN values in OpenSSL 0.9.8.
            // If there's ever a new one that doesn't, translate it here.
            string sn = hashAlgorithmName.Name!;

            int nid = Interop.Crypto.ObjSn2Nid(sn);

            if (nid == Interop.Crypto.NID_undef)
            {
                Interop.Crypto.ErrClearError();
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithmName.Name);
            }

            return nid;
        }

        private static void ValidatePadding(RSAEncryptionPadding padding)
        {
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            if (padding.Mode == RSAEncryptionPaddingMode.Pkcs1)
            {
                // Fail if any options are set other than the mode.
                if (padding != RSAEncryptionPadding.Pkcs1)
                {
                    throw PaddingModeNotSupported();
                }
            }
            else if (padding.Mode != RSAEncryptionPaddingMode.Oaep)
            {
                throw PaddingModeNotSupported();
            }
        }

        private static Exception PaddingModeNotSupported() =>
            new CryptographicException(SR.Cryptography_InvalidPaddingMode);

        private static Exception HashAlgorithmNameNullOrEmpty() =>
            new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, "hashAlgorithm");
    }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
