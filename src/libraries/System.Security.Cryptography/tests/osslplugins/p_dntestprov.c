// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include <string.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

static const char* g_keyPath;
static int g_keyPathLength;

typedef struct dntestprov_loaderctx DNTESTPROV_LOADERCTX;

struct dntestprov_loaderctx
{
    BIO* bio;
    OSSL_DECODER_CTX* decoderCtx;
    OSSL_LIB_CTX* libCtx;
    int done;
};

struct dntestprov_decoder_cb_data
{
    OSSL_CALLBACK* object_cb;
    void* object_cbarg;
};

static DNTESTPROV_LOADERCTX* ctx_from_bio(BIO* bio, OSSL_LIB_CTX* libCtx)
{
    if (bio == NULL)
    {
        return NULL;
    }

    DNTESTPROV_LOADERCTX* ctx = OPENSSL_zalloc(sizeof(DNTESTPROV_LOADERCTX));

    if (ctx == NULL)
    {
        BIO_free(bio);
    }

    ctx->bio = bio;
    ctx->libCtx = libCtx;
    return ctx;
}

static int last_error_is(int lib, int reason)
{
    int err = ERR_peek_last_error();

    return err != 0 && ERR_GET_LIB(err) == lib && ERR_GET_REASON(err) == reason;
}

static void* dntestprov_store_open(void* provctx, const char* uri)
{
    DBG("dntestprov_store_open(%p, \"%s\")\n", provctx, uri);
    if (uri != NULL && g_keyPathLength > 0 && g_keyPathLength < 250)
    {
        char path[300] = { 0 };

        strcpy(path, g_keyPath);

        if (path[g_keyPathLength - 1] != '/')
        {
            path[g_keyPathLength] = '/';
            path[g_keyPathLength + 1] = 0;
        }

        strncat(path, uri, sizeof(path) - 1);

        BIO* bio = BIO_new_file(path, "rb");

        if (bio == NULL)
        {
            if (last_error_is(ERR_LIB_BIO, BIO_R_NO_SUCH_FILE))
            {
                DBG("file not found...\n");
            }
        }

        return ctx_from_bio(bio, provctx);
    }

    return NULL;
}

static void* dntestprov_store_attach(void* provctx, OSSL_CORE_BIO* bio)
{
    DBG("dntestprov_store_attach(%p, \"%p\")\n", provctx, bio);
    return ctx_from_bio(BIO_new_from_core_bio(provctx, bio), provctx);
}

int dntestprov_decoder_cb(
    OSSL_DECODER_INSTANCE* decoder_inst,
    const OSSL_PARAM* params,
    void* construct_data)
{
    struct dntestprov_decoder_cb_data* data = construct_data;
    DBG("dntestprov_decoder_cb\n");

    return data->object_cb(params, data->object_cbarg);
}

static void register_decoder(OSSL_DECODER* decoder, void* arg)
{
    OSSL_DECODER_CTX* decoderCtx = arg;
    OSSL_DECODER_CTX_add_decoder(decoderCtx, decoder);
}

int dntestprov_store_load(
    void* loaderctx,
    OSSL_CALLBACK* object_cb, void* object_cbarg,
    OSSL_PASSPHRASE_CALLBACK* pw_cb, void* pw_cbarg)
{
    DBG("dntestprov_store_load\n");
    DNTESTPROV_LOADERCTX* ctx = loaderctx;

    if (ctx == NULL)
    {
        return 0;
    }

    OSSL_DECODER_CTX* decoderCtx = ctx->decoderCtx;
    int ret = 1;

    if (decoderCtx == NULL)
    {
        decoderCtx = OSSL_DECODER_CTX_new();
        // Just let dntestprov_close free it.
        ctx->decoderCtx = decoderCtx;

        if (decoderCtx == NULL)
        {
            return 0;
        }

        OSSL_LIB_CTX* decoderLibs = OSSL_LIB_CTX_new();
        ret = 0;

        if (decoderLibs != NULL)
        {
            OSSL_PROVIDER* baseProv = OSSL_PROVIDER_load(decoderLibs, "base");
            OSSL_DECODER_do_all_provided(decoderLibs, register_decoder, decoderCtx);

            if (baseProv != NULL &&
                OSSL_DECODER_CTX_add_extra(decoderCtx, decoderLibs, NULL) &&
                OSSL_DECODER_CTX_set_construct(decoderCtx, dntestprov_decoder_cb))
            {
                ret = 1;
            }

            if (baseProv != NULL)
            {
                OSSL_PROVIDER_unload(baseProv);
            }

            OSSL_LIB_CTX_free(decoderLibs);
        }

        if (ret != 1)
        {
            return ret;
        }
    }

    struct dntestprov_decoder_cb_data data = { .object_cb = object_cb, .object_cbarg = object_cbarg };
    OSSL_DECODER_CTX_set_construct_data(decoderCtx, &data);
    OSSL_DECODER_CTX_set_passphrase_cb(decoderCtx, pw_cb, pw_cbarg);

    ERR_set_mark();
    ret = OSSL_DECODER_from_bio(decoderCtx, ctx->bio);

    if (BIO_eof(ctx->bio) && last_error_is(ERR_LIB_OSSL_DECODER, ERR_R_UNSUPPORTED))
    {
        ERR_pop_to_mark();
    }
    else
    {
        ERR_clear_last_mark();
    }

    if (ret == 0)
    {
        ctx->done = 1;
    }

    return ret;
}

static int dntestprov_store_eof(void* loaderctx)
{
    if (loaderctx == NULL)
    {
        return -1;
    }

    DNTESTPROV_LOADERCTX* ctx = loaderctx;
    return ctx->done || ctx->bio == NULL || BIO_eof(ctx->bio);
}

static int dntestprov_store_close(void* loaderctx)
{
    DNTESTPROV_LOADERCTX* ctx = loaderctx;

    if (ctx == NULL)
    {
        return 0;
    }

    if (ctx->decoderCtx != NULL)
    {
        OSSL_DECODER_CTX_free(ctx->decoderCtx);
    }

    if (ctx->bio != NULL)
    {
        BIO_free(ctx->bio);
    }

    OPENSSL_clear_free(ctx, sizeof(DNTESTPROV_LOADERCTX));
    return 1;
}

static const OSSL_DISPATCH g_dntestprov_store_funcs[] =
{
    { OSSL_FUNC_STORE_OPEN, (void(*)(void))dntestprov_store_open },
    { OSSL_FUNC_STORE_ATTACH, (void(*)(void))dntestprov_store_attach },
    { OSSL_FUNC_STORE_LOAD, (void(*)(void))dntestprov_store_load },
    { OSSL_FUNC_STORE_EOF, (void(*)(void))dntestprov_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void(*)(void))dntestprov_store_close },
    { 0 },
};

static const OSSL_ALGORITHM g_dntestprov_stores[] =
{
    { "file", "provider=dntestprov,dntestprov.store", g_dntestprov_store_funcs },
    { 0 },
};

static const OSSL_ALGORITHM* dntestprov_query_operation(void* provctx, int operation_id, int* no_cache)
{
    *no_cache = 0;

    switch (operation_id)
    {
	case OSSL_OP_STORE:
	    return g_dntestprov_stores;
    }

    return NULL;
}

static const OSSL_DISPATCH g_dntestprov_dispatch[] =
{
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void(*)(void))dntestprov_query_operation },
    { 0 },
};

OPENSSL_EXPORT int OSSL_provider_init(
    const OSSL_CORE_HANDLE* handle,
    const OSSL_DISPATCH* in,
    const OSSL_DISPATCH** out,
    void** provctx)
{
    DBG("dntestprov: OSSL_provider_init\n");

    OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);

    if (libctx != NULL)
    {
        g_keyPath = getenv("DNTEST_KEY_PATH");
        g_keyPathLength = g_keyPath == NULL ? 0 : strlen(g_keyPath);

        *out = g_dntestprov_dispatch;
        *provctx = libctx;

        return 1;
    }

    return 0;
}
