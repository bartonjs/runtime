// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "opensslshim.h"
#include "pal_crypto_types.h"
#include "pal_types.h"

#include "../Common/pal_safecrt.h"
#include <assert.h>

#if defined NEED_OPENSSL_1_0 || defined NEED_OPENSSL_1_1

#include "apibridge_30.h"

int local_EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int bits)
{
    return RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, NULL);
}

int local_EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX* ctx, const EVP_MD* md)
{
    // set_rsa_oaep_md doesn't route through RSA_pkey_ctx_ctrl n 1.1, unlike the other set_rsa operations.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
    return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void*)md);
#pragma clang diagnostic pop
}

int local_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX* ctx, int pad_mode)
{
    return RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_RSA_PADDING, pad_mode, NULL);
}

int local_EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX* ctx, int saltlen)
{
    return RSA_pkey_ctx_ctrl(
        ctx, (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY), EVP_PKEY_CTRL_RSA_PSS_SALTLEN, saltlen, NULL);
}

int local_EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX* ctx, const EVP_MD* md)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
    return EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD, 0, (void*)md);
#pragma clang diagnostic pop
}

#endif
