// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace System.DirectoryServices.Protocols
{
    public partial class LdapSessionOptions
    {
        static partial void PALCertFreeCRLContext(IntPtr certPtr);

        partial void SetServerCertificateOption()
        {
            SetLinuxServerCertificateVerification();
        }

        private enum TlsProvider
        {
            Unknown,
            OpenSsl,
            GnuTls,
            MozNss,
        }

        private static volatile bool s_tlsProviderInitialized;
        private static volatile bool s_tlsProviderAvailable;
        private static readonly object s_tlsProviderInitLock = new object();
        private static TlsProvider s_tlsProvider;

        /// <summary>
        /// One-time initialization: detect the TLS provider used by OpenLDAP via
        /// LDAP_OPT_X_TLS_PACKAGE, then delegate to the appropriate provider-specific
        /// initializer to resolve its function pointers.
        /// </summary>
        private static bool InitializeTlsVerificationProvider()
        {
            if (s_tlsProviderInitialized)
            {
                return s_tlsProviderAvailable;
            }

            lock (s_tlsProviderInitLock)
            {
                if (s_tlsProviderInitialized)
                {
                    return s_tlsProviderAvailable;
                }

                IntPtr ldapHandle = Interop.Ldap.s_ldapLibraryHandle;

                if (ldapHandle == IntPtr.Zero)
                {
                    s_tlsProviderInitialized = true;
                    return false;
                }

                // Determine the TLS provider before attempting any provider-specific symbol resolution.
                // LDAP_OPT_X_TLS_PACKAGE is a global option that doesn't require a connection handle.
                IntPtr packagePtr = IntPtr.Zero;
                int error = Interop.Ldap.ldap_get_option_ptr(IntPtr.Zero, LdapOption.LDAP_OPT_X_TLS_PACKAGE, ref packagePtr);

                string tlsPackageName = null;

                if (error == 0 && packagePtr != IntPtr.Zero)
                {
                    tlsPackageName = Marshal.PtrToStringAnsi(packagePtr);
                }

                bool available;

                if (string.Equals(tlsPackageName, "OpenSSL", StringComparison.OrdinalIgnoreCase))
                {
                    s_tlsProvider = TlsProvider.OpenSsl;
                    available = InitializeOpenSsl(ldapHandle);
                }
                else if (string.Equals(tlsPackageName, "GnuTLS", StringComparison.OrdinalIgnoreCase))
                {
                    s_tlsProvider = TlsProvider.GnuTls;
                    available = InitializeGnuTls(ldapHandle);
                }
                else if (string.Equals(tlsPackageName, "MozNSS", StringComparison.OrdinalIgnoreCase))
                {
                    s_tlsProvider = TlsProvider.MozNss;
                    available = InitializeMozNss(ldapHandle);
                }
                else
                {
                    available = false;
                }

                s_tlsProviderAvailable = available;
                s_tlsProviderInitialized = true;

                return available;
            }
        }

        /// <summary>
        /// Callback registered via LDAP_OPT_X_TLS_CONNECT_CB. Called by OpenLDAP during TLS handshake.
        /// Dispatches to the provider-specific setup method based on the detected TLS provider.
        /// </summary>
        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static unsafe void TlsConnectCallback(IntPtr ldapHandle, IntPtr ssl, IntPtr ctx, IntPtr arg)
        {
            if (arg == IntPtr.Zero || ssl == IntPtr.Zero)
            {
                return;
            }

            if (!s_tlsProviderAvailable)
            {
                return;
            }

            GCHandle gcHandle = GCHandle.FromIntPtr(arg);
            LdapSessionOptions options = (LdapSessionOptions)gcHandle.Target;

            if (options?._serverCertificateDelegate is null)
            {
                return;
            }

            switch (s_tlsProvider)
            {
                case TlsProvider.OpenSsl:
                    OpenSslSetupVerification(ssl, arg);
                    break;
                case TlsProvider.GnuTls:
                    GnuTlsSetupVerification(ssl, ctx, arg);
                    break;
                case TlsProvider.MozNss:
                    MozNssSetupVerification(ssl, arg);
                    break;
            }
        }

        /// <summary>
        /// Registers the TLS connect callback on the given LDAP connection handle
        /// so that server certificate verification works on Linux.
        /// </summary>
        private unsafe void SetLinuxServerCertificateVerification()
        {
            if (!InitializeTlsVerificationProvider())
            {
                throw new PlatformNotSupportedException(SR.DirectoryServicesProtocols_PlatformNotSupported);
            }

            if (!_tlsConnectCallbackGCHandle.IsAllocated)
            {
                _tlsConnectCallbackGCHandle = GCHandle.Alloc(this);
            }

            delegate* unmanaged[Cdecl]<IntPtr, IntPtr, IntPtr, IntPtr, void> callbackPtr = &TlsConnectCallback;
            int error = LdapPal.SetFunctionPtrOption(_connection._ldapHandle, LdapOption.LDAP_OPT_X_TLS_CONNECT_CB, callbackPtr);
            ErrorChecking.CheckAndSetLdapError(error);

            IntPtr argValue = GCHandle.ToIntPtr(_tlsConnectCallbackGCHandle);
            error = LdapPal.SetPtrOption(_connection._ldapHandle, LdapOption.LDAP_OPT_X_TLS_CONNECT_ARG, ref argValue);
            ErrorChecking.CheckAndSetLdapError(error);
        }

        private GCHandle _tlsConnectCallbackGCHandle;

        internal void FreeTlsCallbackResources()
        {
            if (_tlsConnectCallbackGCHandle.IsAllocated)
            {
                _tlsConnectCallbackGCHandle.Free();
            }
        }

        private bool _secureSocketLayer;

        /// <summary>
        /// Specifies the path of the directory containing CA certificates in the PEM format.
        /// Multiple directories may be specified by separating with a semi-colon.
        /// </summary>
        /// <remarks>
        /// The certificate files are looked up by the CA subject name hash value where that hash can be
        /// obtained by using, for example, <code>openssl x509 -hash -noout -in CA.crt</code>.
        /// It is a common practice to have the certificate file be a symbolic link to the actual certificate file
        /// which can be done by using <code>openssl rehash .</code> or <code>c_rehash .</code> in the directory
        /// containing the certificate files.
        /// </remarks>
        /// <exception cref="DirectoryNotFoundException">The directory does not exist.</exception>
        [UnsupportedOSPlatform("windows")]
        public string TrustedCertificatesDirectory
        {
            get => GetStringValueHelper(LdapOption.LDAP_OPT_X_TLS_CACERTDIR, releasePtr: true);

            set
            {
                if (!Directory.Exists(value))
                {
                    throw new DirectoryNotFoundException(SR.Format(SR.DirectoryNotFound, value));
                }

                SetStringOptionHelper(LdapOption.LDAP_OPT_X_TLS_CACERTDIR, value);
            }
        }

        public bool SecureSocketLayer
        {
            get
            {
                if (_connection._disposed) throw new ObjectDisposedException(GetType().Name);
                return _secureSocketLayer;
            }
            set
            {
                if (_connection._disposed) throw new ObjectDisposedException(GetType().Name);
                _secureSocketLayer = value;
            }
        }

        public ReferralChasingOptions ReferralChasing
        {
            get
            {
                return GetBoolValueHelper(LdapOption.LDAP_OPT_REFERRALS) ? ReferralChasingOptions.All : ReferralChasingOptions.None;
            }
            set
            {
                if (((value) & (~ReferralChasingOptions.All)) != 0)
                {
                    throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(ReferralChasingOptions));
                }
                if (value != ReferralChasingOptions.None && value != ReferralChasingOptions.All)
                {
                    throw new PlatformNotSupportedException(SR.ReferralChasingOptionsNotSupported);
                }

                SetBoolValueHelper(LdapOption.LDAP_OPT_REFERRALS, value == ReferralChasingOptions.All);
            }
        }

        /// <summary>
        /// Create a new TLS library context.
        /// Calling this is necessary after setting TLS-based options, such as <c>TrustedCertificatesDirectory</c>.
        /// </summary>
        [UnsupportedOSPlatform("windows")]
        public void StartNewTlsSessionContext()
        {
            SetIntValueHelper(LdapOption.LDAP_OPT_X_TLS_NEWCTX, 0);
        }

        // In practice, this apparently rarely if ever contains useful text
        internal string ServerErrorMessage => GetStringValueHelper(LdapOption.LDAP_OPT_ERROR_STRING, true);

        private bool GetBoolValueHelper(LdapOption option)
        {
            if (_connection._disposed) throw new ObjectDisposedException(GetType().Name);

            bool outValue = false;
            int error = LdapPal.GetBoolOption(_connection._ldapHandle, option, ref outValue);
            ErrorChecking.CheckAndSetLdapError(error);

            return outValue;
        }

        private void SetBoolValueHelper(LdapOption option, bool value)
        {
            if (_connection._disposed) throw new ObjectDisposedException(GetType().Name);

            int error = LdapPal.SetBoolOption(_connection._ldapHandle, option, value);

            ErrorChecking.CheckAndSetLdapError(error);
        }

        private void SetStringOptionHelper(LdapOption option, string value)
        {
            if (_connection._disposed) throw new ObjectDisposedException(GetType().Name);

            int error = LdapPal.SetStringOption(_connection._ldapHandle, option, value);

            ErrorChecking.CheckAndSetLdapError(error);
        }
    }
}
