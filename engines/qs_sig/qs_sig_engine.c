#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#ifndef OPENSSL_NO_CMS
# include <openssl/cms.h>
#endif
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hss.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hss_err.h"
#include "qs_sig_engine.h"

// -------------------------------------------------------------------------------------------------
// Local Declarations
// -------------------------------------------------------------------------------------------------

static const char *engine_id = "qs_sig";
static const char *engine_name = "Quantum Safe Signature Engine for OpenSSL";

/* We 0 terminate these lists because that's what gost does.  But we don't
 * count the 0 terminator when we return the number of NIDS. Isn't that
 * wonderful?  Bask in the glory of the -1 below.
 */
static const int qs_sig_pmeth_nids[] = {NID_hss, 0};
static const int qs_sig_ameth_nids[] = {NID_hss, 0};

static int qs_sig_register_meths(void);
static int qs_sig_destroy_meths(void);
static void hss_set_pmeth(EVP_PKEY_METHOD **pmeth);
static void hss_set_ameth(EVP_PKEY_ASN1_METHOD **ameth);

// -------------------------------------------------------------------------------------------------
// Output Utility Function
// -------------------------------------------------------------------------------------------------

int qs_sig_engine_octet_print(BIO *bp, const char *prefix, const ASN1_OCTET_STRING *str, int off)
{
    int n = 0;
    int i = 0;

    if (str == NULL || str->length == 0) {
        return 1;
    }

    if (!BIO_indent(bp, off, QS_SIG_PRETTY_PRINT_LENGTH)) {
        return 0;
    }
      
    if (BIO_printf(bp, "%s", prefix) <= 0) {
        return 0;
    }

    n = str->length;
    for (i = 0; i < n; i++) {
        if ((i % 15) == 0) {
            if (BIO_puts(bp, "\n") <= 0 || !BIO_indent(bp, off + 4, QS_SIG_PRETTY_PRINT_LENGTH)) {
                return 0;
            }
        }

        if (BIO_printf(bp, "%02x%s", str->data[i], ((i + 1) == n) ? "" : ":") <= 0) {
            return 0;
        }
    }

    if (BIO_write(bp, "\n", 1) <= 0) {
        return 0;
    }

    return 1;
}

// -------------------------------------------------------------------------------------------------
// Engine Infrastructure Routines
// -------------------------------------------------------------------------------------------------

static int qs_sig_engine_init(ENGINE *e)
{
    (void) e;
    OpenSSL_add_all_algorithms();

    return 1;
}

static int qs_sig_engine_finish(ENGINE *e)
{
    (void) e;

    return 1;
}

static int qs_sig_engine_destroy(ENGINE *e)
{
    (void) e;

    OBJ_cleanup();
    EVP_cleanup();

    qs_sig_destroy_meths();

    ERR_unload_HSS_strings();

    return 1;
}

static int qs_sig_engine_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                                  const int **nids, int nid)
{
    (void) e;
    if (!pmeth) {
        *nids = qs_sig_pmeth_nids;
        /* In this case, the return value tells the caller how many nids are
         * in the nids list.
         */
        return sizeof(qs_sig_pmeth_nids) / sizeof(int) - 1;
    }

    /* In the following cases, the return value indicates success. */
    if (nid == NID_hss) {
        hss_set_pmeth(pmeth);
        return 1;
    }

    /* In this case, the return value indicates 0 nids or failure. You pick. */
    return 0;
}

static int qs_sig_engine_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
                                       const int **nids, int nid)
{
    (void) e;
    if (!ameth) {
        *nids = qs_sig_ameth_nids;
        /* In this case, the return value tells the caller how many nids are
         * in the nids list.
         */
        return sizeof(qs_sig_ameth_nids) / sizeof(int) - 1;
    }

    /* In the following cases, the return value indicates success. */
    if (nid == NID_hss) {
        hss_set_ameth(ameth);
        return 1;
    }

    /* In this case, the return value indicates 0 nids or failure. */
    return 0;
}

static int qs_sig_bind(ENGINE *e, const char *id)
{
    int ret = 0;
    (void)id;

    if (!ENGINE_set_id(e, engine_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name)) {
        fprintf(stderr, "ENGINE_set_name failed\n");
        goto end;
    }

    if (!ENGINE_set_pkey_meths(e, qs_sig_engine_pkey_meths)) {
        fprintf(stderr, "ENGINE_set_pkey_meths failed\n");
        goto end;
    }

    if (!ENGINE_set_pkey_asn1_meths(e, qs_sig_engine_pkey_asn1_meths)) {
        fprintf(stderr, "ENGINE_set_pkey_asn1_meths failed\n");
        goto end;
    }

    // Init / Teardown functions
    if (!ENGINE_set_destroy_function(e, qs_sig_engine_destroy)
        || !ENGINE_set_init_function(e, qs_sig_engine_init)
        || !ENGINE_set_finish_function(e, qs_sig_engine_finish)) {
        goto end;
    }

    if (!qs_sig_register_meths()) {
        goto end;
    }

    if (!ENGINE_register_pkey_meths(e)) {
        fprintf(stderr, "ENGINE_register_pkey_meths failed\n");
        goto end;
    }

    ERR_load_HSS_strings();
    ret = 1;
end:
    return ret;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_BIND_FN(qs_sig_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif                          /* ndef OPENSSL_NO_DYNAMIC_ENGINE */

static EVP_PKEY_ASN1_METHOD *ameth_hss = NULL;
static EVP_PKEY_METHOD *pmeth_hss = NULL;

static int qs_sig_destroy_meths(void)
{
   /* No memory is deallocated as its taken care of by OpenSSL during engine
    * cleanup.
    */
    ameth_hss = NULL;
    pmeth_hss = NULL;
    return 1;
}

static void hss_set_pmeth(EVP_PKEY_METHOD **pmeth) {
    *pmeth = pmeth_hss;
}

static void hss_set_ameth(EVP_PKEY_ASN1_METHOD **ameth) {
    *ameth = ameth_hss;
}

static int qs_sig_register_meths(void)
{
    int ret = 0;

    if (!hss_register_ameth(NID_hss, &ameth_hss, "HSS", "HSS-Signature")) {
        goto end;
    }

    if (!hss_register_pmeth(NID_hss, &pmeth_hss, 0)) {
        goto end;
    }

    ret = 1;
end:
    return ret;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_qs_sig(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!qs_sig_bind(ret, engine_id)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_qs_sig(void)
{
    ENGINE *toadd;
    if (pmeth_hss)
        return;
    toadd = engine_qs_sig();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#endif
