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

#define OSSL_STORE_INFO_PKEY 4
#define OSSL_STORE_INFO_PUBKEY 3

typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
typedef struct ossl_param_st OSSL_PARAM;
typedef struct ossl_provider_st OSSL_PROVIDER;
typedef struct ossl_store_ctx_st OSSL_STORE_CTX;
typedef struct ossl_store_info_st OSSL_STORE_INFO;
typedef OSSL_STORE_INFO* (*OSSL_STORE_post_process_info_fn)(OSSL_STORE_INFO*, void*);

void ERR_new(void);
void ERR_set_debug(const char *file, int line, const char *func);
void ERR_set_error(int lib, int reason, const char *fmt, ...);
int EVP_CIPHER_get_nid(const EVP_CIPHER *e);
int EVP_MD_get_size(const EVP_MD* md);
int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int bits);
int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX* ctx, const EVP_MD* md);
int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX* ctx, int pad_mode);
int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX* ctx, int saltlen);
int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX* ctx, const EVP_MD* md);
int EVP_PKEY_get_base_id(const EVP_PKEY* pkey);
int EVP_PKEY_get_size(const EVP_PKEY* pkey);
void OSSL_LIB_CTX_free(OSSL_LIB_CTX*);
OSSL_LIB_CTX* OSSL_LIB_CTX_new(void);
OSSL_PROVIDER* OSSL_PROVIDER_load(OSSL_LIB_CTX*, const char* name);
OSSL_PROVIDER* OSSL_PROVIDER_try_load(OSSL_LIB_CTX*, const char* name, int retain_fallbacks);
int OSSL_PROVIDER_unload(OSSL_PROVIDER* prov);
int OSSL_STORE_close(OSSL_STORE_CTX* ctx);
int OSSL_STORE_eof(OSSL_STORE_CTX* ctx);
OSSL_STORE_INFO* OSSL_STORE_load(OSSL_STORE_CTX* ctx);
void OSSL_STORE_INFO_free(OSSL_STORE_INFO* info);
int OSSL_STORE_INFO_get_type(const OSSL_STORE_INFO* info);
EVP_PKEY* OSSL_STORE_INFO_get1_PKEY(const OSSL_STORE_INFO* info);
EVP_PKEY* OSSL_STORE_INFO_get1_PUBKEY(const OSSL_STORE_INFO* info);
OSSL_STORE_CTX* OSSL_STORE_open_ex(
    const char*, OSSL_LIB_CTX*, const char*, const UI_METHOD*, void*, const OSSL_PARAM*, OSSL_STORE_post_process_info_fn post_process, void*);
X509* SSL_get1_peer_certificate(const SSL* ssl);
