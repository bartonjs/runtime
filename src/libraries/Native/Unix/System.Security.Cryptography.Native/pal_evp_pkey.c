// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_evp_pkey.h"

EVP_PKEY* CryptoNative_EvpPkeyCreate()
{
    return EVP_PKEY_new();
}

void CryptoNative_EvpPkeyDestroy(EVP_PKEY* pkey)
{
    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }
}

int32_t CryptoNative_UpRefEvpPkey(EVP_PKEY* pkey)
{
    if (pkey == NULL)
    {
        return 0;
    }

    return EVP_PKEY_up_ref(pkey);
}

int32_t CryptoNative_EvpPKeyKeySize(EVP_PKEY* pkey)
{
    if (pkey == NULL)
    {
        return -1;
    }

    return EVP_PKEY_bits(pkey);
}
