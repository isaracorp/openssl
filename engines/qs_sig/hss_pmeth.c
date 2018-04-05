#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/ossl_typ.h>
#include <openssl/hss.h>

#include "hss_err.h"
#include "qs_sig_engine.h"

#include "hash-sigs/hss.h"

typedef struct {
    /// The hss algorithm (McGrew & Curcio, section 5.5).
    long winternitz_value;

    /// The ots algorithm used during signature creation (McGrew & Curcio,
    /// section 4.10).
    long tree_height;

    /// Size of auxiliary data to use, to speed up signing.
    long aux_length;

    /// Used to write back the updated private key state
    char *private_key_file;
} HSS_PKEY_CTX;

static void hss_teardown(HSS_PKEY_CTX *hssctx) {
    if (hssctx->private_key_file != NULL) {
        OPENSSL_free(hssctx->private_key_file);
        hssctx->private_key_file = NULL;
    }
}

static int hss_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    (void) ctx;
    (void) type;
    (void) p1;
    (void) p2;

    /* This is called to inform us about the hashing algorithm.  So, we implement
     * it to simply return 1 to inform the rest of the system that its no problem.
     */
    return 1;
}

static int hss_pkey_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    HSS_PKEY_CTX *hssctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    if (strcmp(type, set_winternitz_value_ctrl_string) == 0) {
        char *endptr = NULL;
        long int ival = strtol(value, &endptr, 10);
        if (endptr == NULL || *endptr != '\0') {
            return 0;
        }
        switch (ival) {
            case 1: hssctx->winternitz_value = LMOTS_SHA256_N32_W1; break;
            case 2: hssctx->winternitz_value = LMOTS_SHA256_N32_W2; break;
            case 4: hssctx->winternitz_value = LMOTS_SHA256_N32_W4; break;
            case 8: hssctx->winternitz_value = LMOTS_SHA256_N32_W8; break;
            default:
                return 0;
        }
        return 1;
    }

    if (strcmp(type, set_tree_height_ctrl_string) == 0) {
        char *endptr = NULL;
        long int ival = strtol(value, &endptr, 10);
        if (endptr == NULL || *endptr != '\0') {
            return 0;
        }
        switch (ival) {
            case 5: hssctx->tree_height = LMS_SHA256_N32_H5; break;
            case 10: hssctx->tree_height = LMS_SHA256_N32_H10; break;
            case 15: hssctx->tree_height = LMS_SHA256_N32_H15; break;
            case 20: hssctx->tree_height = LMS_SHA256_N32_H20; break;
            case 25: hssctx->tree_height = LMS_SHA256_N32_H25; break;
            default:
                return 0;
        }
        return 1;
    }

    if (strcmp(type, set_hss_aux_length_ctrl_string) == 0) {
        char *endptr = NULL;
        long ival = strtol(value, &endptr, 10);
        if (endptr == NULL || *endptr != '\0') {
            return 0;
        }
        hssctx->aux_length = ival;
        return 1;
    }

    if (strcmp(type, set_hss_private_key_file_ctrl_string) == 0) {
        if (value != NULL && value[0] != '\0') {
            if (hssctx->private_key_file != NULL) {
                OPENSSL_free(hssctx->private_key_file);
            }
            hssctx->private_key_file = BUF_strdup(value);
            if (hssctx->private_key_file == NULL) {
                return 0;
            }
            if (ctx != NULL && pkey != NULL && pkey->pkey.hss != NULL) {
                if (pkey->pkey.hss->private_key_file != NULL) {
                    OPENSSL_free(pkey->pkey.hss->private_key_file);
                }
                pkey->pkey.hss->private_key_file = BUF_strdup(value);
                if (pkey->pkey.hss->private_key_file == NULL) {
                    return 0;
                }
            }
        }
        return 1;
    }

    return 0;
}

static int hss_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int rc = 0;
    HSS *hss = NULL;
    HSS_PKEY_CTX *hssctx = NULL;
    EVP_PKEY *ctx_pkey = NULL;

    /* Validating parameters */
    if (pkey == NULL) {
        HSSerr(HSS_F_HSS_PKEY_KEYGEN, HSS_R_NULL_POINTER_ERROR);
        return 0;
    }

    if (ctx == NULL) {
        HSSerr(HSS_F_HSS_PKEY_KEYGEN, HSS_R_NULL_POINTER_ERROR);
        return 0;
    }

    ctx_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (ctx_pkey != NULL) {
        HSSerr(HSS_F_HSS_PKEY_KEYGEN, HSS_R_EXPECTED_NULL_POINTER);
        return 0;
    }

    hssctx = EVP_PKEY_CTX_get_data(ctx);
    if (hssctx == NULL) {
        HSSerr(HSS_F_HSS_PKEY_KEYGEN, HSS_R_NULL_POINTER_ERROR);
        return 0;
    }

    hss = HSS_new();
    if (hss == NULL) {
        return 0;
    }
    
    if (!EVP_PKEY_assign(pkey, NID_hss, hss)) {
        HSSerr(HSS_F_HSS_PKEY_KEYGEN, HSS_R_PKEY_ASSIGNMENT_ERROR);
        HSS_free(hss);
        return 0;
    }

    if (ctx_pkey == NULL) {
        hss->tree_height = hssctx->tree_height;
        hss->winternitz_value = hssctx->winternitz_value;
        hss->aux_length = hssctx->aux_length;
        if (hss->private_key_file != NULL) {
            OPENSSL_free(hss->private_key_file);
            hss->private_key_file = NULL;
        }
        if (hssctx->private_key_file != NULL) {
            hss->private_key_file = BUF_strdup(hssctx->private_key_file);
            if (hss->private_key_file == NULL) {
                return 0;
            }
        }
    } else {
        /* Note: if error return, pkey is freed by parent routine.
         * This branch should never execute as we don't support parameter
         * generation anymore. However, there might be other reasons why 
         * the context's pkey exists so its good to cover this case.
         */
        if (!EVP_PKEY_copy_parameters(pkey, ctx_pkey)) {
            return 0;
        }
    }

    rc = hss_keygen(hss);
    /* We do not teardown if there is an error as cleanup will be called. */

    return rc;
}

static int hss_pkey_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                         size_t *siglen, const unsigned char *tbs,
                         size_t tbslen)
{
    int ret;
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    HSS_PKEY_CTX *hssctx = EVP_PKEY_CTX_get_data(ctx);
    HSS *hss = EVP_PKEY_get0(pkey);
    int status = 0;

    if (siglen == NULL) {
        HSSerr(HSS_F_HSS_PKEY_SIGN, HSS_R_NULL_SIGNATURE_LENGTH_POINTER);
        return 0;
    }

    if ((sig == NULL) || (tbs == NULL)) {
         /* This is just OpenSSL's friendly way of querying us for the
         * signature size. Note that we can't just sort of sign some random
         * data and then return the size of the signature because that would
         * litterally BURN an OTS!!
         */
        *siglen = hss_sig_size(hss);
        return 1;
    }

    ret = hss_sign(pkey, tbs, tbslen, sig, siglen);
    if (ret <= 0) {
        goto err;
    }

    status = 1;

err:

    if (status == 0) {
        hss_teardown(hssctx);
    }
    return status;
}

static int hss_pkey_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    HSS *hss = pkey->pkey.hss;
    return hss_verify(hss, tbs, tbslen, sig, siglen);
}

static int hss_pkey_init(EVP_PKEY_CTX *ctx)
{
    HSS_PKEY_CTX *hssctx = NULL;

    /* Prevent potential memory leak */
    if (EVP_PKEY_CTX_get_data(ctx) != NULL) {
        return 1;
    }

    hssctx = OPENSSL_malloc(sizeof(HSS_PKEY_CTX));
    if (!hssctx) {
        HSSerr(HSS_F_HSS_PKEY_INIT, HSS_R_MALLOC_FAILURE);
        return 0;
    }

    hssctx->winternitz_value = -1;
    hssctx->tree_height = -1;
    hssctx->aux_length = -1;

    hssctx->private_key_file = NULL;

    EVP_PKEY_CTX_set_data(ctx, hssctx);
    return 1;
}

static void hss_pkey_cleanup(EVP_PKEY_CTX *ctx)
{   
    HSS_PKEY_CTX *hssctx = EVP_PKEY_CTX_get_data(ctx);

    if (hssctx != NULL) {
        hss_teardown(hssctx);
        OPENSSL_free(hssctx);
    }
    EVP_PKEY_CTX_set_data(ctx, NULL);
}

static int hss_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    HSS_PKEY_CTX *dctx, *sctx;
    if (!hss_pkey_init(dst)) {
        return 0;
    }
    sctx = EVP_PKEY_CTX_get_data(src);
    dctx = EVP_PKEY_CTX_get_data(dst);

    dctx->tree_height = sctx->tree_height;
    dctx->winternitz_value = sctx->winternitz_value;
    dctx->aux_length = sctx->aux_length;
    if (dctx->private_key_file != NULL) {
        OPENSSL_free(dctx->private_key_file);
    }
    if (sctx->private_key_file != NULL) {
        dctx->private_key_file = BUF_strdup(sctx->private_key_file);
        if (dctx->private_key_file == NULL) {
            return 0;
        }
    }

    /* Note that we do not worry about I */
    return 1;
}

int hss_register_pmeth(int id, EVP_PKEY_METHOD **pmeth, int flags)
{
    *pmeth = EVP_PKEY_meth_new(id, flags);
    if (!*pmeth) {
        // We don't set error because HSS errors not registered yet.
        return 0;
    }

    EVP_PKEY_meth_set_ctrl(*pmeth,
                           hss_pkey_ctrl,
                           hss_pkey_ctrl_str);
    EVP_PKEY_meth_set_keygen(*pmeth,
                             NULL,
                             hss_pkey_keygen);
    EVP_PKEY_meth_set_sign(*pmeth,
                           NULL,
                           hss_pkey_sign);
    EVP_PKEY_meth_set_verify(*pmeth,
                             NULL,
                             hss_pkey_verify);
    EVP_PKEY_meth_set_init(*pmeth,
                           hss_pkey_init);
    EVP_PKEY_meth_set_cleanup(*pmeth,
                              hss_pkey_cleanup);
    EVP_PKEY_meth_set_copy(*pmeth,
                           hss_pkey_copy);

    return 1;
}

