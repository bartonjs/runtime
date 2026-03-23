// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace System.DirectoryServices.Protocols
{
    public partial class LdapSessionOptions
    {
        /// <summary>
        /// Holds the resolved Mozilla NSS function pointers for the TLS verification callbacks.
        /// </summary>
        private static unsafe class MozNssFunctions
        {
            // SSL_AuthCertificateHook(PRFileDesc *fd, SSLAuthCertificate func, void *arg) → SECStatus
            internal static delegate* unmanaged[Cdecl]<IntPtr, IntPtr, IntPtr, int> SSL_AuthCertificateHook;

            // SSL_PeerCertificate(PRFileDesc *fd) → CERTCertificate* (caller must free)
            internal static delegate* unmanaged[Cdecl]<IntPtr, IntPtr> SSL_PeerCertificate;

            // CERT_DestroyCertificate(CERTCertificate *cert)
            internal static delegate* unmanaged[Cdecl]<IntPtr, void> CERT_DestroyCertificate;

            // CERT_GetCertificateDer(const CERTCertificate *cert, SECItem *derCert) → SECStatus
            internal static delegate* unmanaged[Cdecl]<IntPtr, SECItem*, int> CERT_GetCertificateDer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECItem
        {
            public uint type;
            public IntPtr data;
            public uint len;
        }

        /// <summary>
        /// Resolve Mozilla NSS function pointers from the OpenLDAP library handle.
        /// </summary>
        private static unsafe bool InitializeMozNss(IntPtr ldapHandle)
        {
            if (!NativeLibrary.TryGetExport(ldapHandle, "SSL_AuthCertificateHook", out IntPtr p1) ||
                !NativeLibrary.TryGetExport(ldapHandle, "SSL_PeerCertificate", out IntPtr p2) ||
                !NativeLibrary.TryGetExport(ldapHandle, "CERT_DestroyCertificate", out IntPtr p3) ||
                !NativeLibrary.TryGetExport(ldapHandle, "CERT_GetCertificateDer", out IntPtr p4))
            {
                return false;
            }

            MozNssFunctions.SSL_AuthCertificateHook = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, IntPtr, int>)p1;
            MozNssFunctions.SSL_PeerCertificate = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr>)p2;
            MozNssFunctions.CERT_DestroyCertificate = (delegate* unmanaged[Cdecl]<IntPtr, void>)p3;
            MozNssFunctions.CERT_GetCertificateDer = (delegate* unmanaged[Cdecl]<IntPtr, SECItem*, int>)p4;

            return true;
        }

        /// <summary>
        /// Called from <see cref="TlsConnectCallback"/> when the TLS provider is MozNSS.
        /// Installs our auth certificate hook on the SSL file descriptor.
        /// </summary>
        private static unsafe void MozNssSetupVerification(IntPtr fd, IntPtr arg)
        {
            // SSL_AuthCertificateHook takes its own void* arg, which is passed
            // directly to the callback. We pass our GCHandle through it.
            MozNssFunctions.SSL_AuthCertificateHook(
                fd,
                (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, int, int, int>)&MozNssVerifyCallback,
                arg);
        }

        /// <summary>
        /// Mozilla NSS auth certificate callback.
        /// Signature: SECStatus callback(void *arg, PRFileDesc *fd, PRBool checkSig, PRBool isServer)
        /// Return 0 (SECSuccess) to accept, -1 (SECFailure) to reject.
        /// </summary>
        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static unsafe int MozNssVerifyCallback(IntPtr arg, IntPtr fd, int checkSig, int isServer)
        {
            if (arg == IntPtr.Zero || fd == IntPtr.Zero)
            {
                return -1;
            }

            GCHandle gcHandle = GCHandle.FromIntPtr(arg);
            LdapSessionOptions options = (LdapSessionOptions)gcHandle.Target;

            if (options?._serverCertificateDelegate is null)
            {
                return 0;
            }

            IntPtr cert = MozNssFunctions.SSL_PeerCertificate(fd);

            if (cert == IntPtr.Zero)
            {
                return -1;
            }

            X509Certificate certificate;

            try
            {
                SECItem derItem;
                int status = MozNssFunctions.CERT_GetCertificateDer(cert, &derItem);

                // SECSuccess = 0
                if (status != 0 || derItem.data == IntPtr.Zero || derItem.len == 0)
                {
                    return -1;
                }

                byte[] derBytes = new byte[derItem.len];
                Marshal.Copy(derItem.data, derBytes, 0, (int)derItem.len);

                certificate = X509CertificateLoader.LoadCertificate(derBytes);
            }
            catch
            {
                return -1;
            }
            finally
            {
                MozNssFunctions.CERT_DestroyCertificate(cert);
            }

            try
            {
                bool accepted = options._serverCertificateDelegate(options._connection, certificate);
                return accepted ? 0 : -1;
            }
            catch
            {
                return -1;
            }
        }
    }
}
