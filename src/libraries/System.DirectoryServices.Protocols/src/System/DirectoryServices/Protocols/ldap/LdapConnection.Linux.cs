// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;

namespace System.DirectoryServices.Protocols
{
    public partial class LdapConnection
    {
        // Linux doesn't support setting FQDN so we mark the flag as if it is already set so we don't make a call to set it again.
        private bool _setFQDNDone = true;
        private LdapControlArray _tlsServerControls;
        private LdapControlArray _tlsClientControls;
        private bool _startTls;

        partial void DisposePartial(bool disposing)
        {
            // Native resources, free unconditionally.
            _tlsClientControls.Release();
            _tlsServerControls.Release();
        }

        private void InternalInitConnectionHandle(string hostname)
        {
            if ((LdapDirectoryIdentifier)_directoryIdentifier == null)
            {
                throw new NullReferenceException();
            }

            _ldapHandle = new ConnectionHandle();
        }

        private int InternalConnectToServer()
        {
            // In Linux you don't have to call Connect after calling init. You
            // directly call bind. However, we set the URI for the connection
            // here instead of during initialization because we need access to
            // the SessionOptions property to properly define it, which is not
            // available during init.
            Debug.Assert(!_ldapHandle.IsInvalid);

            string scheme = null;
            LdapDirectoryIdentifier directoryIdentifier = (LdapDirectoryIdentifier)_directoryIdentifier;
            if (directoryIdentifier.Connectionless)
            {
                scheme = "cldap://";
            }
            else if (SessionOptions.SecureSocketLayer)
            {
                scheme = "ldaps://";
            }
            else
            {
                scheme = "ldap://";
            }

            string uris = null;
            string[] servers = directoryIdentifier.Servers;
            if (servers != null && servers.Length != 0)
            {
                StringBuilder temp = new StringBuilder(200);
                for (int i = 0; i < servers.Length; i++)
                {
                    if (i != 0)
                    {
                        temp.Append(' ');
                    }
                    temp.Append(scheme);
                    temp.Append(servers[i]);
                    temp.Append(':');
                    temp.Append(directoryIdentifier.PortNumber);
                }
                if (temp.Length != 0)
                {
                    uris = temp.ToString();
                }
            }
            else
            {
                uris = $"{scheme}:{directoryIdentifier.PortNumber}";
            }

            int error =  LdapPal.SetStringOption(_ldapHandle, LdapOption.LDAP_OPT_URI, uris);

            if (error == 0 && _startTls)
            {
                int serverReturnValue = 0;
                IntPtr message = IntPtr.Zero;

                error = LdapPal.StartTls(
                    _ldapHandle,
                    ref serverReturnValue,
                    ref message,
                    _tlsServerControls.DangerousGetHandle(),
                    _tlsClientControls.DangerousGetHandle());

                // With OpenLDAP we don't get a message back, so we don't need to free it.
                Debug.Assert(message == IntPtr.Zero);

                if (error == (int)ResultCode.Other)
                {
                    error = serverReturnValue;
                }

                if (error != 0)
                {
                    string errorMessage = OperationErrorMappings.MapResultCode(error);
                    ExtendedResponse response = new ExtendedResponse(null, null, (ResultCode)error, errorMessage, null);
                    response.ResponseName = "1.3.6.1.4.1.1466.20037";
                    throw new TlsOperationException(response);
                }
            }

            return error;
        }

        private int InternalBind(NetworkCredential tempCredential, SEC_WINNT_AUTH_IDENTITY_EX cred, BindMethod method)
        {
            int error;
            if (tempCredential == null && (AuthType == AuthType.External || AuthType == AuthType.Kerberos))
            {
                error = BindSasl();
            }
            else
            {
                error = LdapPal.BindToDirectory(_ldapHandle, cred.user, cred.password);
            }

            return error;
        }

        private int BindSasl()
        {
            SaslDefaultCredentials defaults = GetSaslDefaults();
            IntPtr ptrToDefaults = Marshal.AllocHGlobal(Marshal.SizeOf(defaults));
            Marshal.StructureToPtr(defaults, ptrToDefaults, false);
            try
            {
                return Interop.Ldap.ldap_sasl_interactive_bind(_ldapHandle, null, Interop.KerberosDefaultMechanism, IntPtr.Zero, IntPtr.Zero, Interop.LDAP_SASL_QUIET, LdapPal.SaslInteractionProcedure, ptrToDefaults);
            }
            finally
            {
                GC.KeepAlive(defaults); //Making sure we keep it in scope as we will still use ptrToDefaults
                Marshal.FreeHGlobal(ptrToDefaults);
            }
        }

        private SaslDefaultCredentials GetSaslDefaults()
        {
            var defaults = new SaslDefaultCredentials { mech = Interop.KerberosDefaultMechanism };
            IntPtr outValue = IntPtr.Zero;
            int error = Interop.Ldap.ldap_get_option_ptr(_ldapHandle, LdapOption.LDAP_OPT_X_SASL_REALM, ref outValue);
            if (error == 0 && outValue != IntPtr.Zero)
            {
                defaults.realm = Marshal.PtrToStringAnsi(outValue);
            }
            error = Interop.Ldap.ldap_get_option_ptr(_ldapHandle, LdapOption.LDAP_OPT_X_SASL_AUTHCID, ref outValue);
            if (error == 0 && outValue != IntPtr.Zero)
            {
                defaults.authcid = Marshal.PtrToStringAnsi(outValue);
            }
            error = Interop.Ldap.ldap_get_option_ptr(_ldapHandle, LdapOption.LDAP_OPT_X_SASL_AUTHZID, ref outValue);
            if (error == 0 && outValue != IntPtr.Zero)
            {
                defaults.authzid = Marshal.PtrToStringAnsi(outValue);
            }
            return defaults;
        }

        internal void StartTransportLayerSecurityCore(DirectoryControlCollection controls)
        {
            // https://docs.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_start_tls_sw#remarks
            //
            // If already bound or already called, say no.
            if (_startTls || _connected)
            {
                const ResultCode Error = ResultCode.UnwillingToPerform;
                string errorMessage = OperationErrorMappings.MapResultCode((int)Error);
                ExtendedResponse response = new ExtendedResponse(null, null, Error, errorMessage, null);
                response.ResponseName = "1.3.6.1.4.1.1466.20037";
                throw new TlsOperationException(response);
            }

            _startTls = true;
            _tlsServerControls = LdapControlArray.Create(controls, serverControl: true);
            _tlsClientControls = LdapControlArray.Create(controls, serverControl: false);
        }
    }
}
