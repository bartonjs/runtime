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
        /// Holds the resolved GnuTLS function pointers for the TLS verification callbacks.
        /// </summary>
        private static unsafe class GnuTlsFunctions
        {
            // gnutls_certificate_set_verify_function(gnutls_certificate_credentials_t cred, verify_func cb)
            internal static delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void> gnutls_certificate_set_verify_function;

            // gnutls_session_set_ptr(gnutls_session_t session, void *ptr)
            internal static delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void> gnutls_session_set_ptr;

            // gnutls_session_get_ptr(gnutls_session_t session) → void*
            internal static delegate* unmanaged[Cdecl]<IntPtr, IntPtr> gnutls_session_get_ptr;

            // gnutls_certificate_get_peers(gnutls_session_t session, unsigned int *list_size) → const gnutls_datum_t*
            internal static delegate* unmanaged[Cdecl]<IntPtr, uint*, IntPtr> gnutls_certificate_get_peers;
        }

        /// <summary>
        /// Resolve GnuTLS function pointers from the OpenLDAP library handle.
        /// </summary>
        private static unsafe bool InitializeGnuTls(IntPtr ldapHandle)
        {
            if (!NativeLibrary.TryGetExport(ldapHandle, "gnutls_certificate_set_verify_function", out IntPtr p1) ||
                !NativeLibrary.TryGetExport(ldapHandle, "gnutls_session_set_ptr", out IntPtr p2) ||
                !NativeLibrary.TryGetExport(ldapHandle, "gnutls_session_get_ptr", out IntPtr p3) ||
                !NativeLibrary.TryGetExport(ldapHandle, "gnutls_certificate_get_peers", out IntPtr p4))
            {
                return false;
            }

            GnuTlsFunctions.gnutls_certificate_set_verify_function = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void>)p1;
            GnuTlsFunctions.gnutls_session_set_ptr = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void>)p2;
            GnuTlsFunctions.gnutls_session_get_ptr = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr>)p3;
            GnuTlsFunctions.gnutls_certificate_get_peers = (delegate* unmanaged[Cdecl]<IntPtr, uint*, IntPtr>)p4;

            return true;
        }

        /// <summary>
        /// Called from <see cref="TlsConnectCallback"/> when the TLS provider is GnuTLS.
        /// Installs our verify callback on the credentials and stashes the managed context on the session.
        /// </summary>
        private static unsafe void GnuTlsSetupVerification(IntPtr session, IntPtr cred, IntPtr arg)
        {
            // Stash the GCHandle on the session so the verify callback can retrieve it.
            GnuTlsFunctions.gnutls_session_set_ptr(session, arg);

            // Install our verify callback on the certificate credentials object.
            GnuTlsFunctions.gnutls_certificate_set_verify_function(
                cred,
                (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int>)&GnuTlsVerifyCallback);
        }

        /// <summary>
        /// GnuTLS verify callback. Called during the handshake to verify the peer certificate.
        /// Return 0 to accept, non-zero to reject.
        /// </summary>
        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static unsafe int GnuTlsVerifyCallback(IntPtr session)
        {
            if (session == IntPtr.Zero)
            {
                return -1;
            }

            IntPtr arg = GnuTlsFunctions.gnutls_session_get_ptr(session);

            if (arg == IntPtr.Zero)
            {
                return -1;
            }

            GCHandle gcHandle = GCHandle.FromIntPtr(arg);
            LdapSessionOptions options = (LdapSessionOptions)gcHandle.Target;

            if (options?._serverCertificateDelegate is null)
            {
                return 0;
            }

            // Get the peer certificate chain. The first element is the leaf/server certificate.
            // gnutls_certificate_get_peers returns a pointer to an array of gnutls_datum_t,
            // which are already DER-encoded.
            uint listSize;
            IntPtr certListPtr = GnuTlsFunctions.gnutls_certificate_get_peers(session, &listSize);

            if (certListPtr == IntPtr.Zero || listSize == 0)
            {
                return -1;
            }

            X509Certificate certificate;

            try
            {
                // gnutls_datum_t is { unsigned char *data; unsigned int size; }
                IntPtr dataPtr = Marshal.ReadIntPtr(certListPtr);
                uint dataSize = (uint)Marshal.ReadInt32(certListPtr + IntPtr.Size);

                if (dataPtr == IntPtr.Zero || dataSize == 0)
                {
                    return -1;
                }

                byte[] derBytes = new byte[dataSize];
                Marshal.Copy(dataPtr, derBytes, 0, (int)dataSize);

                certificate = X509CertificateLoader.LoadCertificate(derBytes);
            }
            catch
            {
                return -1;
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
