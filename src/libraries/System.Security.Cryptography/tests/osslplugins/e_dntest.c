
#include <string.h>
#include <openssl/engine.h>

static const char* g_engineId = "dntest";
static const char* g_engineName = "DotNet Test ENGINE";
static const char* g_keyPath;
static int g_keyPathLength;

static EVP_PKEY* load_priv(BIO* file)
{
    EVP_PKEY* ret = NULL;
    PKCS8_PRIV_KEY_INFO* p8info = PEM_read_bio_PKCS8_PRIV_KEY_INFO(file, NULL, NULL, NULL);
    BIO_free(file);

    if (p8info != NULL)
    {
        ret = EVP_PKCS82PKEY(p8info);
        PKCS8_PRIV_KEY_INFO_free(p8info);
    }

    return ret;
}

static EVP_PKEY* load_key(
    const char* keyId,
    EVP_PKEY* (*load_func)(BIO* bio))
{
    EVP_PKEY* ret = NULL;

    if (keyId != NULL && g_keyPathLength > 0 && g_keyPathLength < 250)
    {
        char path[300] = { 0 };

        strcpy(path, g_keyPath);

        if (path[g_keyPathLength - 1] != '/')
        {
            path[g_keyPathLength] = '/';
            path[g_keyPathLength + 1] = 0;
        }

        strncat(path, keyId, sizeof(path) - 1);

        BIO* file = BIO_new_file(path, "rb");

        if (file != NULL)
        {
            ret = load_func(file);
        }
    }

    return ret;
}

static EVP_PKEY* dntest_load_privkey(
    ENGINE* engine,
    const char* keyId,
    UI_METHOD* ui_method,
    void* callback_data)
{
    return load_key(keyId, load_priv);
}

static int bind(ENGINE* engine, const char* id)
{
    int ret = 1;

    if (ret != 1 ||
        !ENGINE_set_id(engine, g_engineId) ||
        !ENGINE_set_name(engine, g_engineName) ||
        !ENGINE_set_RSA(engine, RSA_PKCS1_OpenSSL()) ||
        !ENGINE_set_load_privkey_function(engine, dntest_load_privkey))
    {
        ret = 0;
    }

    g_keyPath = getenv("DNTEST_KEY_PATH");
    g_keyPathLength = g_keyPath == NULL ? 0 : strlen(g_keyPath);

    return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
