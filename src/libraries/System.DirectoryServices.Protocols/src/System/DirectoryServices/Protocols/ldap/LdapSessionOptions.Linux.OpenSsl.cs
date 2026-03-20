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
        /// Holds the resolved OpenSSL function pointers for the TLS verification callbacks.
        /// Initialized once via <see cref="InitializeOpenSslFunctionPointers"/> when a
        /// VerifyServerCertificate callback is registered on a Linux connection.
        /// </summary>
        private static unsafe class OpenSslFunctions
        {
            // SSL_set_verify(SSL *ssl, int mode, verify_callback cb)
            internal static delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, void> SSL_set_verify;

            // SSL_get_ex_new_index(long argl, void *argp, ...) → int
            internal static delegate* unmanaged[Cdecl]<long, IntPtr, IntPtr, IntPtr, IntPtr, int> SSL_get_ex_new_index;

            // SSL_set_ex_data(SSL *ssl, int idx, void *data) → int
            internal static delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, int> SSL_set_ex_data;

            // SSL_get_ex_data(SSL *ssl, int idx) → void*
            internal static delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr> SSL_get_ex_data;

            // X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx, int idx) → void*
            internal static delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr> X509_STORE_CTX_get_ex_data;

            // SSL_get_ex_data_X509_STORE_CTX_idx() → int
            internal static delegate* unmanaged[Cdecl]<int> SSL_get_ex_data_X509_STORE_CTX_idx;

            // X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx) → int
            internal static delegate* unmanaged[Cdecl]<IntPtr, int> X509_STORE_CTX_get_error_depth;

            // X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx) → X509* (borrowed)
            internal static delegate* unmanaged[Cdecl]<IntPtr, IntPtr> X509_STORE_CTX_get_current_cert;

            // i2d_X509(X509 *x, unsigned char **out) → int
            internal static delegate* unmanaged[Cdecl]<IntPtr, IntPtr*, int> i2d_X509;

            // X509_free(X509 *x)
            internal static delegate* unmanaged[Cdecl]<IntPtr, void> X509_free;

            // The ex_data index allocated for storing our managed context on SSL objects.
            internal static int s_exDataIndex = -1;
        }

        private static volatile bool s_openSslInitialized;
        private static volatile bool s_openSslAvailable;
        private static readonly object s_openSslInitLock = new object();

        /// <summary>
        /// One-time initialization: resolve all needed OpenSSL function pointers
        /// from the OpenLDAP library handle (which searches libldap's dependency tree).
        /// </summary>
        private static unsafe bool InitializeOpenSslFunctionPointers()
        {
            if (s_openSslInitialized)
            {
                return s_openSslAvailable;
            }

            lock (s_openSslInitLock)
            {
                if (s_openSslInitialized)
                {
                    return s_openSslAvailable;
                }

                IntPtr ldapHandle = Interop.Ldap.s_ldapLibraryHandle;

                if (ldapHandle == IntPtr.Zero)
                {
                    s_openSslInitialized = true;
                    s_openSslAvailable = false;
                    return false;
                }

                if (!NativeLibrary.TryGetExport(ldapHandle, "SSL_set_verify", out IntPtr p1) ||
                    !NativeLibrary.TryGetExport(ldapHandle, "SSL_get_ex_new_index", out IntPtr p2) ||
                    !NativeLibrary.TryGetExport(ldapHandle, "SSL_set_ex_data", out IntPtr p3) ||
                    !NativeLibrary.TryGetExport(ldapHandle, "SSL_get_ex_data", out IntPtr p4) ||
                    !NativeLibrary.TryGetExport(ldapHandle, "X509_STORE_CTX_get_ex_data", out IntPtr p5) ||
                    !NativeLibrary.TryGetExport(ldapHandle, "SSL_get_ex_data_X509_STORE_CTX_idx", out IntPtr p6) ||
                    !NativeLibrary.TryGetExport(ldapHandle, "X509_STORE_CTX_get_error_depth", out IntPtr p7) ||
                    !NativeLibrary.TryGetExport(ldapHandle, "X509_STORE_CTX_get_current_cert", out IntPtr p8) ||
                    !NativeLibrary.TryGetExport(ldapHandle, "i2d_X509", out IntPtr p9) ||
                    !NativeLibrary.TryGetExport(ldapHandle, "X509_free", out IntPtr p10))
                {
                    s_openSslInitialized = true;
                    s_openSslAvailable = false;
                    return false;
                }

                OpenSslFunctions.SSL_set_verify = (delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, void>)p1;
                OpenSslFunctions.SSL_get_ex_new_index = (delegate* unmanaged[Cdecl]<long, IntPtr, IntPtr, IntPtr, IntPtr, int>)p2;
                OpenSslFunctions.SSL_set_ex_data = (delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, int>)p3;
                OpenSslFunctions.SSL_get_ex_data = (delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr>)p4;
                OpenSslFunctions.X509_STORE_CTX_get_ex_data = (delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr>)p5;
                OpenSslFunctions.SSL_get_ex_data_X509_STORE_CTX_idx = (delegate* unmanaged[Cdecl]<int>)p6;
                OpenSslFunctions.X509_STORE_CTX_get_error_depth = (delegate* unmanaged[Cdecl]<IntPtr, int>)p7;
                OpenSslFunctions.X509_STORE_CTX_get_current_cert = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr>)p8;
                OpenSslFunctions.i2d_X509 = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr*, int>)p9;
                OpenSslFunctions.X509_free = (delegate* unmanaged[Cdecl]<IntPtr, void>)p10;

                // CRYPTO_EX_INDEX_SSL = 0, and the new/dup/free callbacks are null.
                int idx = OpenSslFunctions.SSL_get_ex_new_index(0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                if (idx < 0)
                {
                    s_openSslInitialized = true;
                    s_openSslAvailable = false;
                    return false;
                }

                OpenSslFunctions.s_exDataIndex = idx;

                s_openSslAvailable = true;
                s_openSslInitialized = true;
                return true;
            }
        }

        /// <summary>
        /// Callback registered via LDAP_OPT_X_TLS_CONNECT_CB. Called by OpenLDAP during TLS handshake.
        /// For OpenSSL backends, installs our custom SSL verify callback on the connection.
        /// </summary>
        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static unsafe void TlsConnectCallback(IntPtr ldapHandle, IntPtr ssl, IntPtr ctx, IntPtr arg)
        {
            if (arg == IntPtr.Zero || ssl == IntPtr.Zero)
            {
                return;
            }

            if (!s_openSslAvailable)
            {
                return;
            }

            // arg is a GCHandle to the LdapSessionOptions instance.
            GCHandle gcHandle = GCHandle.FromIntPtr(arg);
            LdapSessionOptions options = (LdapSessionOptions)gcHandle.Target;

            if (options?._serverCertificateDelegate is null)
            {
                return;
            }

            // Stash the GCHandle on the SSL object so the verify callback can retrieve it.
            OpenSslFunctions.SSL_set_ex_data(ssl, OpenSslFunctions.s_exDataIndex, arg);

            // SSL_VERIFY_PEER = 0x01. This tells OpenSSL to invoke our verify callback.
            const int SSL_VERIFY_PEER = 0x01;
            OpenSslFunctions.SSL_set_verify(
                ssl,
                SSL_VERIFY_PEER,
                (IntPtr)(delegate* unmanaged[Cdecl]<int, IntPtr, int>)&OpenSslVerifyCallback);
        }

        /// <summary>
        /// OpenSSL verify callback. Called for each certificate in the chain.
        /// We only invoke the user delegate at depth 0 (the leaf/server certificate)
        /// to match Windows LDAP behavior.
        /// </summary>
        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static unsafe int OpenSslVerifyCallback(int preverifyOk, IntPtr x509StoreCtx)
        {
            if (x509StoreCtx == IntPtr.Zero)
            {
                return 0;
            }

            int depth = OpenSslFunctions.X509_STORE_CTX_get_error_depth(x509StoreCtx);

            // For non-leaf certificates, pass through OpenSSL's own verification result.
            if (depth != 0)
            {
                return preverifyOk;
            }

            // Retrieve the SSL object from the X509_STORE_CTX, then our stashed context from it.
            int sslIdx = OpenSslFunctions.SSL_get_ex_data_X509_STORE_CTX_idx();
            IntPtr ssl = OpenSslFunctions.X509_STORE_CTX_get_ex_data(x509StoreCtx, sslIdx);

            if (ssl == IntPtr.Zero)
            {
                return preverifyOk;
            }

            IntPtr arg = OpenSslFunctions.SSL_get_ex_data(ssl, OpenSslFunctions.s_exDataIndex);

            if (arg == IntPtr.Zero)
            {
                return preverifyOk;
            }

            GCHandle gcHandle = GCHandle.FromIntPtr(arg);
            LdapSessionOptions options = (LdapSessionOptions)gcHandle.Target;

            if (options?._serverCertificateDelegate is null)
            {
                return preverifyOk;
            }

            // Get the leaf certificate from the store context (borrowed pointer, no free needed).
            IntPtr x509 = OpenSslFunctions.X509_STORE_CTX_get_current_cert(x509StoreCtx);

            if (x509 == IntPtr.Zero)
            {
                return 0;
            }

            X509Certificate certificate = null;

            try
            {
                // Encode the certificate as DER. First call with null to get the length.
                int derLen = OpenSslFunctions.i2d_X509(x509, null);

                if (derLen <= 0)
                {
                    return 0;
                }

                byte[] derBytes = new byte[derLen];

                fixed (byte* derPtr = derBytes)
                {
                    IntPtr derOut = (IntPtr)derPtr;
                    int written = OpenSslFunctions.i2d_X509(x509, &derOut);

                    if (written <= 0)
                    {
                        return 0;
                    }
                }

                certificate = X509CertificateLoader.LoadCertificate(derBytes);
            }
            catch
            {
                return 0;
            }

            try
            {
                bool accepted = options._serverCertificateDelegate(options._connection, certificate);
                return accepted ? 1 : 0;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Registers the TLS connect callback on the given LDAP connection handle
        /// so that server certificate verification works on Linux via OpenSSL.
        /// </summary>
        private unsafe void SetLinuxServerCertificateVerification()
        {
            if (!InitializeOpenSslFunctionPointers())
            {
                throw new PlatformNotSupportedException(SR.DirectoryServicesProtocols_PlatformNotSupported);
            }

            // Check whether the TLS package is OpenSSL.
            IntPtr packagePtr = IntPtr.Zero;
            int error = LdapPal.GetPtrOption(_connection._ldapHandle, LdapOption.LDAP_OPT_X_TLS_PACKAGE, ref packagePtr);

            if (error != 0 || packagePtr == IntPtr.Zero)
            {
                throw new PlatformNotSupportedException(SR.DirectoryServicesProtocols_PlatformNotSupported);
            }

            string tlsPackage = Marshal.PtrToStringAnsi(packagePtr);

            // TODO: Support GnuTLS and MozNSS in the future.
            if (!string.Equals(tlsPackage, "OpenSSL", StringComparison.OrdinalIgnoreCase))
            {
                throw new PlatformNotSupportedException(SR.DirectoryServicesProtocols_PlatformNotSupported);
            }

            // Allocate a GCHandle for the TLS connect callback arg if we haven't already.
            if (!_tlsConnectCallbackGCHandle.IsAllocated)
            {
                _tlsConnectCallbackGCHandle = GCHandle.Alloc(this);
            }

            // Register the TLS connect callback.
            delegate* unmanaged[Cdecl]<IntPtr, IntPtr, IntPtr, IntPtr, void> callbackPtr = &TlsConnectCallback;
            error = LdapPal.SetFunctionPtrOption(_connection._ldapHandle, LdapOption.LDAP_OPT_X_TLS_CONNECT_CB, callbackPtr);
            ErrorChecking.CheckAndSetLdapError(error);

            // Register the arg (our GCHandle) that will be passed to the callback.
            IntPtr argValue = GCHandle.ToIntPtr(_tlsConnectCallbackGCHandle);
            error = LdapPal.SetPtrOption(_connection._ldapHandle, LdapOption.LDAP_OPT_X_TLS_CONNECT_ARG, ref argValue);
            ErrorChecking.CheckAndSetLdapError(error);
        }

        private GCHandle _tlsConnectCallbackGCHandle;

        internal void FreeTlsCallbackResources(bool disposing)
        {
            _ = disposing;

            // Whether or not we're disposing, we need to free the GCHandle.
            if (_tlsConnectCallbackGCHandle.IsAllocated)
            {
                _tlsConnectCallbackGCHandle.Free();
            }
        }
    }
}
