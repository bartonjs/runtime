// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// Function prototypes unique to OpenSSL 3.0

#pragma once
#include "pal_types.h"

#undef EVP_PKEY_CTX_set_rsa_keygen_bits
#undef EVP_PKEY_CTX_set_rsa_oaep_md
#undef EVP_PKEY_CTX_set_rsa_padding
#undef EVP_PKEY_CTX_set_rsa_pss_saltlen
#undef EVP_PKEY_CTX_set_signature_md

int32_t EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int32_t bits);
int32_t EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX* ctx, const EVP_MD* md);
int32_t EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX* ctx, int32_t pad_mode);
int32_t EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX* ctx, int32_t saltlen);
int32_t EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX* ctx, const EVP_MD* md);
