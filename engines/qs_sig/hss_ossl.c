/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/hss.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "hss_err.h"
#include "qs_sig_engine.h"

#include "hash-sigs/hss.h"

#define NUM_HSS_LEVELS 1

/**
 * HSS Callbacks
 */

static bool hss_generate_random_callback(void *output, size_t length)
{
    if (!RAND_bytes(output, length)) {
        return false;
    }
    return true;
}

static bool hss_generate_private_key_callback(unsigned char *private_key, size_t len_private_key, void *context)
{
    ASN1_OCTET_STRING *priv_key = context;
    if (!priv_key) {
        return false;
    }
    if (!ASN1_OCTET_STRING_set(priv_key, private_key, (int)len_private_key)) {
        return false;
    }
    return true;
}

static bool hss_read_private_key_callback(unsigned char *private_key, size_t len_private_key, void *context)
{
    HSS *hss = context;
    if (!hss || !hss->priv_key || !hss->priv_key->data) {
        return false;
    }
    if ((size_t)hss->priv_key->length < len_private_key) {
        return false;
    }

    CRYPTO_r_lock(CRYPTO_LOCK_HSS);
    memcpy(private_key, hss->priv_key->data, len_private_key);
    CRYPTO_r_unlock(CRYPTO_LOCK_HSS);

    return true;
}

static bool hss_update_private_key_callback(unsigned char *private_key, size_t len_private_key, void *context)
{
    BIO *out = NULL;
    HSS *hss = NULL;
    EVP_PKEY *pkey = context;
    if (!context) {
        return false;
    }
    hss = EVP_PKEY_get0(pkey);
    if (!hss || !hss->priv_key || !hss->priv_key->data) {
        return false;
    }
    if ((size_t)hss->priv_key->length < len_private_key) {
        return false;
    }

    /* This lock protects the internal private key memory, as well as writing
     * to the private key file, however if the caller is also attempting to
     * read from the private key file at the same time there could still be
     * issues since the caller doens't use this lock. For the EST demo we've
     * determined that the caller either already uses a lock with a larger
     * scope which would protect the reading and this writing, or the caller
     * reads from the file only once, before launching threads which could
     * write back to it.  In that case, this lock is sufficient. */
    CRYPTO_w_lock(CRYPTO_LOCK_HSS);

    memcpy(hss->priv_key->data, private_key, len_private_key);

    /**
     * Write the updated private key out to file. HSS keys are stateful and one-time-signatures
     * must not be reused, so we must update the non-volatile key.
     */
    if (hss->private_key_file != NULL) {
        if (!(out = BIO_new_file(hss->private_key_file, "wb"))) {
            CRYPTO_w_unlock(CRYPTO_LOCK_HSS);
            return false;
        }
        if (!PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL)) {
            BIO_free_all(out);
            CRYPTO_w_unlock(CRYPTO_LOCK_HSS);
            return false;
        }
        BIO_free_all(out);
    }

    CRYPTO_w_unlock(CRYPTO_LOCK_HSS);

    return true;
}

/* In hss_sign() we will convert to ASN1.  This means adding
 * 8 more bytes.  I think it might be tag, size, and flags.  There are no
 * flags, so it will be zero.
 */

#define HSS_ASN1_ADDITIONAL_STUFF 4

size_t hss_sig_size(const HSS *r)
{
    size_t sig_size = 0;

    param_set_t lm_array[NUM_HSS_LEVELS] = { r->tree_height };
    param_set_t ots_array[NUM_HSS_LEVELS] = { r->winternitz_value };

    sig_size = hss_get_signature_len(NUM_HSS_LEVELS, lm_array, ots_array);
    if (sig_size == 0) {
        HSSerr(HSS_F_HSS_SIG_SIZE, HSS_R_INVALID_PARAM_VALUE);
        goto err;
    }

err:
    if (sig_size == 0) {
        return 0;
    }
    return sig_size + HSS_ASN1_ADDITIONAL_STUFF;
}

static void free_working_key(void *working_key) {
    hss_free_working_key(working_key);
}

int hss_load_working_key(HSS *hss)
{
    unsigned char *aux_data = NULL;
    size_t aux_length = 0;
    struct hss_extra_info extra_info;
    hss_init_extra_info(&extra_info);
    hss_extra_info_set_threads(&extra_info, 4);

    if (!hss->engine_working_key) {
        if (hss->aux_data != NULL) {
            aux_data = hss->aux_data->data;
            aux_length = hss->aux_data->length;
        }
        hss->engine_working_key = hss_load_private_key(
            hss_read_private_key_callback,
            hss,
            0, /* Use minimal memory */
            aux_data, aux_length,
            &extra_info);
        if (hss->engine_working_key == NULL) {
            HSSerr(HSS_F_HSS_LOAD_WORKING_KEY, HSS_R_SYSTEM_FAILURE);
            return 0;
        }
        hss->free_engine_working_key = free_working_key;
    }
    return 1;
}

static ASN1_OCTET_STRING *hss_do_sign(const unsigned char *dgst, size_t dlen, EVP_PKEY *pkey)
{   
    bool hss_ret = false;
    ASN1_OCTET_STRING *signature = NULL;
    HSS *hss = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;

    struct hss_extra_info extra_info;
    hss_init_extra_info(&extra_info);
    hss_extra_info_set_threads(&extra_info, 1);

    hss = EVP_PKEY_get0(pkey);

    /* Loads the working key if it hasn't already been loaded */
    if (!hss_load_working_key(hss)) {
        return 0;
    }

    sig_len = hss_get_signature_len_from_working_key(hss->engine_working_key);
    if (sig_len == 0) {
        HSSerr(HSS_F_HSS_DO_SIGN, HSS_R_SYSTEM_FAILURE);
        goto err;
    }

    sig = OPENSSL_malloc(sig_len);
    if (sig == NULL) {
        HSSerr(HSS_F_HSS_DO_SIGN, HSS_R_MALLOC_FAILURE);
        goto err;
    }

    hss_ret = hss_generate_signature(
        hss->engine_working_key,
        hss_update_private_key_callback, pkey,
        dgst, dlen,
        sig, sig_len,
        &extra_info);
    if (!hss_ret) {
        HSSerr(HSS_F_HSS_DO_SIGN, HSS_R_SYSTEM_FAILURE);
        goto err;
    }

    signature = ASN1_OCTET_STRING_new();
    if (signature == NULL) {
        goto err;
    }

    /* If this fails, the next function will catch it */
    if (!ASN1_OCTET_STRING_set(signature, sig, (int)sig_len)) {
        HSSerr(HSS_F_HSS_DO_SIGN, HSS_R_MALLOC_FAILURE);
        ASN1_OCTET_STRING_free(signature);
        signature = NULL;
    }

err:
    if (sig != NULL) {
        OPENSSL_free(sig);
    }

    return signature;
}

static int hss_do_verify(const unsigned char *dgst, size_t dlen,
                              ASN1_OCTET_STRING *sig, HSS *hss)
{
   
    int status = 0;
    bool hss_ret = false;

    struct hss_extra_info extra_info;
    hss_init_extra_info(&extra_info);
    hss_extra_info_set_threads(&extra_info, 1);

    hss_ret = hss_validate_signature(
        hss->pub_key->data,
        dgst, dlen,
        sig->data, (size_t)sig->length,
        &extra_info);
    if (!hss_ret) {
        HSSerr(HSS_F_HSS_DO_VERIFY, HSS_R_SYSTEM_FAILURE);
        goto err;
    }

    status = 1;

err:
    return status;
}

int hss_keygen(HSS *hss)
{
    int status = 0;
    bool hss_ret = false;

    ASN1_OCTET_STRING *pub_key = NULL;
    ASN1_OCTET_STRING *priv_key = NULL;
    ASN1_OCTET_STRING *aux_data = NULL;

    param_set_t lm_array[NUM_HSS_LEVELS] = { hss->tree_height };
    param_set_t ots_array[NUM_HSS_LEVELS] = { hss->winternitz_value };

    size_t hss_public_key_length = 0;
    unsigned char *hss_public_key = NULL;

    struct hss_extra_info extra_info;

    /* Cap at INT_MAX because the ASN.1 octet strings are measured with int */
    int aux_length = (hss->aux_length < 0 || hss->aux_length > INT_MAX) ? INT_MAX : hss->aux_length;
    size_t hss_aux_data_length = hss_get_aux_data_len(aux_length, NUM_HSS_LEVELS, lm_array, ots_array);
    unsigned char *hss_aux_data = NULL;

    hss_init_extra_info(&extra_info);
    hss_extra_info_set_threads(&extra_info, 4);

    hss_aux_data = OPENSSL_malloc(hss_aux_data_length);
    if (hss_aux_data == NULL) {
        HSSerr(HSS_F_HSS_KEYGEN, HSS_R_MALLOC_FAILURE);
        goto err;
    }

    hss_public_key_length = hss_get_public_key_len(NUM_HSS_LEVELS, lm_array, ots_array);
    if (hss_public_key_length == 0) {
        HSSerr(HSS_F_HSS_KEYGEN, HSS_R_INVALID_PARAM_VALUE);
        goto err;
    }

    hss_public_key = OPENSSL_malloc(hss_public_key_length);
    if (hss_public_key == NULL) {
        HSSerr(HSS_F_HSS_KEYGEN, HSS_R_MALLOC_FAILURE);
        goto err;
    }

    if (hss->aux_data == NULL) {
        aux_data = ASN1_OCTET_STRING_new();
        if (aux_data == NULL) {
            HSSerr(HSS_F_HSS_KEYGEN, HSS_R_MALLOC_FAILURE);
            goto err;
        }
    } else {
        aux_data = hss->aux_data;
    }

    if (hss->pub_key == NULL) {
        pub_key = ASN1_OCTET_STRING_new();
        if (pub_key == NULL) {
            HSSerr(HSS_F_HSS_KEYGEN, HSS_R_MALLOC_FAILURE);
            goto err;
        }
    } else {
        pub_key = hss->pub_key;
    }

    if (hss->priv_key == NULL) {
        priv_key = ASN1_OCTET_STRING_new();
        if (priv_key == NULL) {
            HSSerr(HSS_F_HSS_KEYGEN, HSS_R_MALLOC_FAILURE);
            goto err;
        }
    } else {
        priv_key = hss->priv_key;
    }

    hss_ret = hss_generate_private_key(
        hss_generate_random_callback,
        NUM_HSS_LEVELS,
        lm_array, ots_array,
        hss_generate_private_key_callback, priv_key,
        hss_public_key, hss_public_key_length,
        hss_aux_data, hss_aux_data_length,
        &extra_info);
    if (!hss_ret) {
        HSSerr(HSS_F_HSS_KEYGEN, HSS_R_SYSTEM_FAILURE);
        goto err;
    }

    if (!ASN1_OCTET_STRING_set(pub_key, hss_public_key, (int)hss_public_key_length)) {
        goto err;
    }

    if (!ASN1_OCTET_STRING_set(aux_data, hss_aux_data, (int)hss_aux_data_length)) {
        goto err;
    }

    hss->priv_key = priv_key;
    hss->pub_key = pub_key;
    hss->aux_data = aux_data;

    if (!hss_load_working_key(hss)) {
        goto err;
    }

    status = 1;

 err:

    OPENSSL_free(hss_public_key);
    OPENSSL_cleanse(hss_aux_data, hss_aux_data_length);
    OPENSSL_free(hss_aux_data);

    if ((pub_key != NULL) && (hss->pub_key == NULL)) {
        ASN1_OCTET_STRING_free(pub_key);
    }

    if ((priv_key != NULL) && (hss->priv_key == NULL)) {
        OPENSSL_cleanse(priv_key->data, (size_t)priv_key->length);
        ASN1_OCTET_STRING_free(priv_key);
    }

    if ((aux_data != NULL) && (hss->aux_data == NULL)) {
        OPENSSL_cleanse(aux_data->data, (size_t)aux_data->length);
        ASN1_OCTET_STRING_free(aux_data);
    }

    return status;
}

int hss_sign(EVP_PKEY *pkey,
                  const unsigned char *dgst, const size_t dlen,
                  unsigned char *sig, size_t *siglen)
{
    ASN1_OCTET_STRING *s;
    RAND_seed(dgst, (int)dlen);
    s = hss_do_sign(dgst, dlen, pkey);
    if (s == NULL) {
        /* hss_do_sign() sets the errors */
        *siglen = 0;
        return (0);
    }
    *siglen = (size_t)i2d_ASN1_OCTET_STRING(s, &sig);
    ASN1_OCTET_STRING_free(s);
    return (1);
}

/* data has already been hashed (probably with SHA or SHA-1). */

int hss_verify(HSS *hss, const unsigned char *dgst, size_t dlen,
                    const unsigned char *sig, size_t siglen)
{
    ASN1_OCTET_STRING *s;
    const unsigned char *p = sig;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ASN1_OCTET_STRING_new();
    if (s == NULL) {
        return (ret);
    }
    if (d2i_ASN1_OCTET_STRING(&s, &p, (int)siglen) == NULL) {
        goto err;
    }
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ASN1_OCTET_STRING(s, &der);
    if (derlen != (int)siglen || memcmp(sig, der, (unsigned long)derlen)) {
        HSSerr(HSS_F_HSS_VERIFY, HSS_R_DECODE_ERROR);
        goto err;
    }
    ret = hss_do_verify(dgst, dlen, s, hss);

 err:
    if (derlen > 0) {
        OPENSSL_cleanse(der, (size_t)derlen);
        OPENSSL_free(der);
    }
    ASN1_OCTET_STRING_free(s);
    return (ret);
}
