// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    public sealed partial class RSAOpenSsl : RSA
    {
        public RSAOpenSsl(RSAParameters parameters)
        {
            // Make _key be non-null before calling ImportParameters
            _key = new Lazy<SafeEvpPKeyHandle>();
            ImportParameters(parameters);
        }

        /// <summary>
        /// Create an RSAOpenSsl from an existing <see cref="IntPtr"/> whose value is an
        /// existing OpenSSL <c>RSA*</c>.
        /// </summary>
        /// <remarks>
        /// This method will increase the reference count of the <c>RSA*</c>, the caller should
        /// continue to manage the lifetime of their reference.
        /// </remarks>
        /// <param name="handle">A pointer to an OpenSSL <c>RSA*</c></param>
        /// <exception cref="ArgumentException"><paramref name="handle" /> is invalid</exception>
        public RSAOpenSsl(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
                throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(handle));

            using (SafeRsaHandle rsaHandle = SafeRsaHandle.DuplicateHandle(handle))
            {
                SafeEvpPKeyHandle pkey = Interop.Crypto.EvpPkeyCreate();

                if (!Interop.Crypto.EvpPkeySetRsa(pkey, rsaHandle))
                {
                    pkey.Dispose();
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }

                // Use ForceSet instead of the property setter to ensure that LegalKeySizes doesn't interfere
                // with the already loaded key.
                ForceSetKeySize(Interop.Crypto.EvpPKeyKeySize(pkey));
                _key = new Lazy<SafeEvpPKeyHandle>(() => pkey, isThreadSafe: true);
            }
        }

        /// <summary>
        /// Create an RSAOpenSsl from an <see cref="SafeEvpPKeyHandle"/> whose value is an existing
        /// OpenSSL <c>EVP_PKEY*</c> wrapping an <c>RSA*</c>
        /// </summary>
        /// <param name="pkeyHandle">A SafeHandle for an OpenSSL <c>EVP_PKEY*</c></param>
        /// <exception cref="ArgumentNullException"><paramref name="pkeyHandle"/> is <c>null</c></exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="pkeyHandle"/> <see cref="Runtime.InteropServices.SafeHandle.IsInvalid" />
        /// </exception>
        /// <exception cref="CryptographicException"><paramref name="pkeyHandle"/> is not a valid enveloped <c>RSA*</c></exception>
        public RSAOpenSsl(SafeEvpPKeyHandle pkeyHandle)
        {
            if (pkeyHandle == null)
                throw new ArgumentNullException(nameof(pkeyHandle));
            if (pkeyHandle.IsInvalid)
                throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(pkeyHandle));

            // TODO: There's probably an EVP_PKEY_dup.
            using (SafeRsaHandle rsa = Interop.Crypto.EvpPkeyGetRsa(pkeyHandle))
            {
                if (rsa.IsInvalid)
                {
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }

                SafeEvpPKeyHandle pkey = Interop.Crypto.EvpPkeyCreate();

                if (!Interop.Crypto.EvpPkeySetRsa(pkey, rsa))
                {
                    pkey.Dispose();
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }

                // Use ForceSet instead of the property setter to ensure that LegalKeySizes doesn't interfere
                // with the already loaded key.
                ForceSetKeySize(Interop.Crypto.EvpPKeyKeySize(pkey));
                _key = new Lazy<SafeEvpPKeyHandle>(() => pkey, isThreadSafe: true);
            }
        }

        /// <summary>
        /// Obtain a SafeHandle version of an EVP_PKEY* which wraps an RSA* equivalent
        /// to the current key for this instance.
        /// </summary>
        /// <returns>A SafeHandle for the RSA key in OpenSSL</returns>
        public SafeEvpPKeyHandle DuplicateKeyHandle()
        {
            SafeEvpPKeyHandle curPKey = _key.Value;
            // Temporary blockless using, pending refactor.
            // TODO: EVP_PKEY_dup?
            using SafeRsaHandle currentKey = Interop.Crypto.EvpPkeyGetRsa(curPKey);
            SafeEvpPKeyHandle pkeyHandle = Interop.Crypto.EvpPkeyCreate();

            try
            {
                // Wrapping our key in an EVP_PKEY will up_ref our key.
                // When the EVP_PKEY is Disposed it will down_ref the key.
                // So everything should be copacetic.
                if (!Interop.Crypto.EvpPkeySetRsa(pkeyHandle, currentKey))
                {
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }

                return pkeyHandle;
            }
            catch
            {
                pkeyHandle.Dispose();
                throw;
            }
        }
    }
}
