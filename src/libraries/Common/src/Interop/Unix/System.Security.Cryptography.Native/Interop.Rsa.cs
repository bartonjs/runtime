// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RsaCreate")]
        internal static extern SafeRsaHandle RsaCreate();

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RsaUpRef")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool RsaUpRef(IntPtr rsa);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RsaDestroy")]
        internal static extern void RsaDestroy(IntPtr rsa);

        internal static SafeRsaHandle DecodeRsaPublicKey(ReadOnlySpan<byte> buf) =>
            DecodeRsaPublicKey(ref MemoryMarshal.GetReference(buf), buf.Length);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_DecodeRsaPublicKey")]
        private static extern SafeRsaHandle DecodeRsaPublicKey(ref byte buf, int len);

        internal static int RsaPublicEncrypt(
            int flen,
            ReadOnlySpan<byte> from,
            Span<byte> to,
            SafeRsaHandle rsa,
            RsaPadding padding) =>
            RsaPublicEncrypt(flen, ref MemoryMarshal.GetReference(from), ref MemoryMarshal.GetReference(to), rsa, padding);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RsaPublicEncrypt")]
        private static extern int RsaPublicEncrypt(
            int flen,
            ref byte from,
            ref byte to,
            SafeRsaHandle rsa,
            RsaPadding padding);

        internal static int RsaEncrypt(
            SafeEvpPKeyHandle pkey,
            ReadOnlySpan<byte> data,
            RSAEncryptionPaddingMode paddingMode,
            IntPtr digestAlgorithm,
            Span<byte> destination) =>
            CryptoNative_RsaEncrypt(
                pkey,
                ref MemoryMarshal.GetReference(data),
                data.Length,
                paddingMode,
                digestAlgorithm,
                ref MemoryMarshal.GetReference(destination));

        [DllImport(Libraries.CryptoNative)]
        private static extern int CryptoNative_RsaEncrypt(
            SafeEvpPKeyHandle pkey,
            ref byte data,
            int dataLength,
            RSAEncryptionPaddingMode paddingMode,
            IntPtr digestAlgorithm,
            ref byte destination);

        internal static int RsaDecrypt(
            SafeEvpPKeyHandle pkey,
            ReadOnlySpan<byte> data,
            RSAEncryptionPaddingMode paddingMode,
            IntPtr digestAlgorithm,
            Span<byte> destination) =>
            CryptoNative_RsaDecrypt(
                pkey,
                ref MemoryMarshal.GetReference(data),
                data.Length,
                paddingMode,
                digestAlgorithm,
                ref MemoryMarshal.GetReference(destination));

        [DllImport(Libraries.CryptoNative)]
        private static extern int CryptoNative_RsaDecrypt(
            SafeEvpPKeyHandle pkey,
            ref byte data,
            int dataLength,
            RSAEncryptionPaddingMode paddingMode,
            IntPtr digestAlgorithm,
            ref byte destination);

        internal static int RsaVerificationPrimitive(
            ReadOnlySpan<byte> from,
            Span<byte> to,
            SafeRsaHandle rsa) =>
            RsaVerificationPrimitive(from.Length, ref MemoryMarshal.GetReference(from), ref MemoryMarshal.GetReference(to), rsa);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RsaVerificationPrimitive")]
        private static extern int RsaVerificationPrimitive(
            int flen,
            ref byte from,
            ref byte to,
            SafeRsaHandle rsa);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RsaSize")]
        internal static extern int RsaSize(SafeRsaHandle rsa);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RsaGenerateKey")]
        private static extern SafeEvpPKeyHandle CryptoNative_RsaGenerateKey(int keySize);

        internal static SafeEvpPKeyHandle RsaGenerateKey(int keySize)
        {
            SafeEvpPKeyHandle pkey = CryptoNative_RsaGenerateKey(keySize);

            if (pkey.IsInvalid)
            {
                pkey.Dispose();
                throw CreateOpenSslCryptographicException();
            }

            return pkey;
        }

        internal static int RsaSignHash(
            SafeEvpPKeyHandle pkey,
            RSASignaturePaddingMode paddingMode,
            IntPtr digest,
            ReadOnlySpan<byte> hash,
            Span<byte> destination)
        {
            int ret = CryptoNative_RsaSignHash(
                pkey,
                paddingMode,
                digest,
                ref MemoryMarshal.GetReference(hash),
                hash.Length,
                ref MemoryMarshal.GetReference(destination),
                out int bytesWritten);

            if (ret != 1)
            {
                Debug.Assert(ret == 0);
                throw CreateOpenSslCryptographicException();
            }

            return bytesWritten;
        }

        [DllImport(Libraries.CryptoNative)]
        private static extern int CryptoNative_RsaSignHash(
            SafeEvpPKeyHandle pkey,
            RSASignaturePaddingMode paddingMode,
            IntPtr digest,
            ref byte hash,
            int hashLen,
            ref byte dest,
            out int sigLen);

        internal static bool RsaVerifyHash(
            SafeEvpPKeyHandle pkey,
            RSASignaturePaddingMode paddingMode,
            IntPtr digest,
            ReadOnlySpan<byte> hash,
            ReadOnlySpan<byte> signature)
        {
            int ret = CryptoNative_RsaVerifyHash(
                pkey,
                paddingMode,
                digest,
                ref MemoryMarshal.GetReference(hash),
                hash.Length,
                ref MemoryMarshal.GetReference(signature),
                signature.Length);

            if (ret == int.MinValue)
            {
                Debug.Fail("Shim reports API usage error");
                throw new CryptographicException();
            }

            if (ret < 0)
            {
                throw CreateOpenSslCryptographicException();
            }

            Debug.Assert(ret < 2);
            return ret == 1;
        }

        [DllImport(Libraries.CryptoNative)]
        private static extern int CryptoNative_RsaVerifyHash(
            SafeEvpPKeyHandle pkey,
            RSASignaturePaddingMode paddingMode,
            IntPtr digest,
            ref byte hash,
            int hashLen,
            ref byte signature,
            int sigLen);

        internal static bool RsaVerify(int type, ReadOnlySpan<byte> m, ReadOnlySpan<byte> sigbuf, SafeRsaHandle rsa)
        {
            bool ret = RsaVerify(
                type,
                ref MemoryMarshal.GetReference(m),
                m.Length,
                ref MemoryMarshal.GetReference(sigbuf),
                sigbuf.Length,
                rsa);

            if (!ret)
            {
                ErrClearError();
            }

            return ret;
        }


        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RsaVerify")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RsaVerify(int type, ref byte m, int m_len, ref byte sigbuf, int siglen, SafeRsaHandle rsa);

        internal static SafeBioHandle ExportRSAPublicKey(SafeEvpPKeyHandle pkey)
        {
            SafeBioHandle bio = CryptoNative_ExportRSAPublicKey(pkey);

            if (bio.IsInvalid)
            {
                bio.Dispose();
                throw CreateOpenSslCryptographicException();
            }

            return bio;
        }

        [DllImport(Libraries.CryptoNative)]
        private static extern SafeBioHandle CryptoNative_ExportRSAPublicKey(SafeEvpPKeyHandle pkey);

        internal static SafeBioHandle ExportRSAPrivateKey(SafeEvpPKeyHandle pkey)
        {
            SafeBioHandle bio = CryptoNative_ExportRSAPrivateKey(pkey);

            if (bio.IsInvalid)
            {
                bio.Dispose();
                throw CreateOpenSslCryptographicException();
            }

            return bio;
        }

        [DllImport(Libraries.CryptoNative)]
        private static extern SafeBioHandle CryptoNative_ExportRSAPrivateKey(SafeEvpPKeyHandle pkey);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_SetRsaParameters")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetRsaParameters(
            SafeRsaHandle key,
            byte[]? n,
            int nLength,
            byte[]? e,
            int eLength,
            byte[]? d,
            int dLength,
            byte[]? p,
            int pLength,
            byte[]? dmp1,
            int dmp1Length,
            byte[]? q,
            int qLength,
            byte[]? dmq1,
            int dmq1Length,
            byte[]? iqmp,
            int iqmpLength);

        internal enum RsaPadding : int
        {
            Pkcs1 = 0,
            OaepSHA1 = 1,
            NoPadding = 2,
        }
    }
}
