#include <stdio.h>
#include <stdint.h>

#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/hss.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_CMS
# include <openssl/cms.h>
#endif

#include "hss_err.h"
#include "qs_sig_engine.h"

#include "hash-sigs/hss.h"

// AMETH
////////////////////////////////////////////////

static void hss_pkey_free(EVP_PKEY *key)
{
    if (key->pkey.hss) {
        HSS_free(key->pkey.hss);
    }
}

static int hss_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
    case ASN1_PKEY_CTRL_PKCS7_SIGN:
        if (arg1 == 0) {
            int snid, hnid;
            X509_ALGOR *alg1, *alg2;
            PKCS7_SIGNER_INFO_get0_algs(arg2, NULL, &alg1, &alg2);
            if (alg1 == NULL || alg1->algorithm == NULL) {
                return -1;
            }
            hnid = OBJ_obj2nid(alg1->algorithm);
            if (hnid == NID_undef) {
                return -1;
            }
            if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey))) {
                return -1;
            }
            X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
        }
        return 1;
#ifndef OPENSSL_NO_CMS
    case ASN1_PKEY_CTRL_CMS_SIGN:
        if (arg1 == 0) {
            int snid, hnid;
            X509_ALGOR *alg1, *alg2;
            CMS_SignerInfo_get0_algs(arg2, NULL, NULL, &alg1, &alg2);
            if (alg1 == NULL || alg1->algorithm == NULL) {
                return -1;
            }
            hnid = OBJ_obj2nid(alg1->algorithm);
            if (hnid == NID_undef) {
                return -1;
            }
            if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey))) {
                return -1;
            }
            X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
        }
        return 1;

    case ASN1_PKEY_CTRL_CMS_RI_TYPE:
        *(int *)arg2 = CMS_RECIPINFO_NONE;
        return 1;
#endif

    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_sha512;
        return 2;

    default:
        return -2;

    }

}

static int hss_pkey_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
{   
    const unsigned char *p;
    int pklen = 0;
    X509_ALGOR *palg = NULL;
    ASN1_OBJECT *palg_obj = NULL;
    void *_pval = NULL;
    ASN1_STRING *pval = NULL;
    int ptype = V_ASN1_UNDEF;
    HSS *hss = NULL;
    HSS *param = NULL;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8)) {
        HSSerr(HSS_F_HSS_PKEY_PRIV_DECODE, HSS_R_PKCS8_DECODE_ERROR);
        return 0;
    }

    X509_ALGOR_get0(&palg_obj, &ptype, &_pval, palg);
    pval = _pval;

    if (pval == NULL) {
        HSSerr(HSS_F_HSS_PKEY_PRIV_DECODE, HSS_R_ASN1_DECODE_ERROR);
        return 0;
    }

    if (OBJ_obj2nid(palg_obj) != NID_hss) {
        HSSerr(HSS_F_HSS_PKEY_PRIV_DECODE, HSS_R_ASN1_DECODE_ERROR);
        return 0;
    }

    if (ptype != V_ASN1_SEQUENCE) {
        HSSerr(HSS_F_HSS_PKEY_PRIV_DECODE, HSS_R_ASN1_DECODE_ERROR);
        return 0;
    }

    hss = d2i_HSSPrivateKey(NULL, &p, pklen);
    p = pval->data;

    param = d2i_HSSparams(NULL, &p, pval->length);
    if ((param == NULL) || (hss == NULL)) {
        HSS_free(param);
        HSS_free(hss);
        HSSerr(HSS_F_HSS_PKEY_PRIV_DECODE, HSS_R_ASN1_DECODE_ERROR);
        return 0;
    }

    hss->winternitz_value = param->winternitz_value;
    hss->tree_height = param->tree_height;

    if (!hss_load_working_key(hss)) {
        HSS_free(hss);
        return 0;
    }

    if (!EVP_PKEY_assign(pkey, NID_hss, hss)) {
        HSS_free(param);
        HSS_free(hss);
        HSSerr(HSS_F_HSS_PKEY_PRIV_DECODE, HSS_R_PKEY_ASSIGNMENT_ERROR);
        return 0;
    }

    HSS_free(param);

    return 1;
}

static int hss_pkey_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    unsigned char *rk = NULL;
    int rklen;
    ASN1_STRING *param = ASN1_STRING_new();

    rklen = i2d_HSSPrivateKey(pkey->pkey.hss, &rk);

    if (rklen <= 0) {
        HSSerr(HSS_F_HSS_PKEY_PRIV_ENCODE, HSS_R_ASN1_ENCODE_ERROR);
        return 0;
    }

    param->length = i2d_HSSparams(pkey->pkey.hss, &param->data);
    if (param->length <= 0) {
        ASN1_STRING_free(param);
        HSSerr(HSS_F_HSS_PKEY_PRIV_ENCODE, HSS_R_ASN1_ENCODE_ERROR);
        return 0;
    }
    param->type = V_ASN1_SEQUENCE;

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_hss), 0,
                         V_ASN1_SEQUENCE, param, rk, rklen)) {
        OPENSSL_cleanse(rk, (size_t)rklen);
        OPENSSL_free(rk);
        ASN1_STRING_free(param);
        HSSerr(HSS_F_HSS_PKEY_PRIV_ENCODE, HSS_R_PKCS8_ENCODE_ERROR);
        return 0;
    }

    return 1;
}

static int do_hss_print(BIO *bp, const HSS *x, int off, int ptype)
{
    int ret = 0;

    const ASN1_OCTET_STRING *priv_key, *pub_key, *aux_data;
    int winternitz_value, tree_height;

    if (ptype == 2) {
        priv_key = x->priv_key;
        aux_data = x->aux_data;
    } else {
        priv_key = NULL;
        aux_data = NULL;
    }

    if (ptype > 0) {
        pub_key = x->pub_key;
    } else {
        pub_key = NULL;
    }

    switch(x->winternitz_value) {
        case LMOTS_SHA256_N32_W1: winternitz_value = 1; break;
        case LMOTS_SHA256_N32_W2: winternitz_value = 2; break;
        case LMOTS_SHA256_N32_W4: winternitz_value = 4; break;
        case LMOTS_SHA256_N32_W8: winternitz_value = 8; break;
        default: winternitz_value = -1; break;
    }

    switch(x->tree_height) {
        case LMS_SHA256_N32_H5: tree_height = 5; break;
        case LMS_SHA256_N32_H10: tree_height = 10; break;
        case LMS_SHA256_N32_H15: tree_height = 15; break;
        case LMS_SHA256_N32_H20: tree_height = 20; break;
        case LMS_SHA256_N32_H25: tree_height = 25; break;
        default: tree_height = -1; break;
    }

    if (!qs_sig_engine_octet_print(bp, "Public Key:", pub_key, off)) {
        goto err;
    }

    if (priv_key) {
        if (!qs_sig_engine_octet_print(bp, "Private Key:", priv_key, off)) {
            goto err;
        }
        if (!qs_sig_engine_octet_print(bp, "Aux Data:", aux_data, off)) {
            goto err;
        }
    }

    if (!BIO_indent(bp, off, QS_SIG_PRETTY_PRINT_LENGTH)) {
        goto err;
    }
    if (BIO_printf(bp, "Winternitz Value: %d (0x%08X)\n", winternitz_value, (unsigned int)x->winternitz_value) <= 0) {
        goto err;
    }

    if (!BIO_indent(bp, off, QS_SIG_PRETTY_PRINT_LENGTH)) {
        goto err;
    }
    if (BIO_printf(bp, "Tree Height: %d (0x%08X)\n", tree_height, (unsigned int)x->tree_height) <= 0) {
        goto err;
    }

    ret = 1;

 err:

    return ret;
}

static int hss_pkey_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    (void) ctx;
    return do_hss_print(bp, pkey->pkey.hss, indent, 2);
}

static int hss_pkey_param_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                           ASN1_PCTX *ctx)
{
    (void) ctx;
    return do_hss_print(bp, pkey->pkey.hss, indent, 0);
}

static int hss_pkey_param_decode(EVP_PKEY *pkey,
                            const unsigned char **pder, int derlen)
{
    HSS *hss = d2i_HSSparams(NULL, pder, derlen);
    if (hss == NULL) {
        HSSerr(HSS_F_HSS_PKEY_PARAM_DECODE, HSS_R_ASN1_PARAMETER_DECODE_ERROR);
        return 0;
    }
    if (!EVP_PKEY_assign(pkey, NID_hss, hss)) {
        HSSerr(HSS_F_HSS_PKEY_PARAM_DECODE, HSS_R_PKEY_ASSIGNMENT_ERROR);
        return 0;
    }
    return 1;
}

static int hss_pkey_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_HSSparams(pkey->pkey.hss, pder);
}

static int hss_pkey_missing_parameters(const EVP_PKEY *pkey)
{
    if ((pkey->pkey.hss->winternitz_value == -1)
        || (pkey->pkey.hss->tree_height == -1)) {
        return 1;
    }
    // This is returning false, not an error.
    return 0;
}

static int hss_pkey_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)
{

    to->pkey.hss->winternitz_value = from->pkey.hss->winternitz_value;
    to->pkey.hss->tree_height = from->pkey.hss->tree_height;
    return 1;
}

static int hss_pkey_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{   

    if (a->pkey.hss->winternitz_value != b->pkey.hss->winternitz_value ||
        a->pkey.hss->tree_height != b->pkey.hss->tree_height) {
        // This is returning false, not an error.
        return 0;
    } else {
        return 1;
    }
}

static int hss_pkey_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p = NULL;
    int pklen = 0;
    X509_ALGOR *palg = NULL;
    ASN1_OBJECT *palg_obj = NULL;
    void *_pval = NULL;
    ASN1_STRING *pval = NULL;
    int ptype = V_ASN1_UNDEF;
    HSS *hss = NULL;
    HSS *param = NULL;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey)) {
        HSSerr(HSS_F_HSS_PKEY_PUB_DECODE, HSS_R_X509_DECODE_ERROR);
        return 0;
    }

    X509_ALGOR_get0(&palg_obj, &ptype, &_pval, palg);
    pval = _pval;

    if (pval == NULL) {
        HSSerr(HSS_F_HSS_PKEY_PUB_DECODE, HSS_R_ASN1_DECODE_ERROR);
        return 0;
    }

    if (OBJ_obj2nid(palg_obj) != NID_hss) {
        HSSerr(HSS_F_HSS_PKEY_PUB_DECODE, HSS_R_ASN1_DECODE_ERROR);
        return 0;
    }

    if (ptype != V_ASN1_SEQUENCE) {
        HSSerr(HSS_F_HSS_PKEY_PUB_DECODE, HSS_R_ASN1_DECODE_ERROR);
        return 0;
    }

    hss = d2i_HSSPublicKey(NULL, &p, pklen);

    p = pval->data;
    param = d2i_HSSparams(NULL, &p, pval->length);

    if ((param == NULL) || (hss == NULL)) {
        HSS_free(param);
        HSS_free(hss);
        HSSerr(HSS_F_HSS_PKEY_PUB_DECODE, HSS_R_ASN1_DECODE_ERROR);
        return 0;
    }
    hss->winternitz_value = param->winternitz_value;
    hss->tree_height = param->tree_height;

    if (!EVP_PKEY_assign(pkey, NID_hss, hss)) {
        HSSerr(HSS_F_HSS_PKEY_PUB_DECODE, HSS_R_PKEY_ASSIGNMENT_ERROR);
        HSS_free(param);
        HSS_free(hss);
        return 0;
    }

    HSS_free(param);
    return 1;
}

static int hss_pkey_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{   
    unsigned char *penc = NULL;
    int penclen;
    ASN1_STRING *param = ASN1_STRING_new();

    penclen = i2d_HSSPublicKey(pkey->pkey.hss, &penc);
    if (penclen <= 0) {
        HSSerr(HSS_F_HSS_PKEY_PUB_ENCODE, HSS_R_ASN1_ENCODE_ERROR);
        return 0;
    }

    param->length = i2d_HSSparams(pkey->pkey.hss, &param->data);
    if (param->length <= 0) {
        ASN1_STRING_free(param);
        HSSerr(HSS_F_HSS_PKEY_PUB_ENCODE, HSS_R_ASN1_ENCODE_ERROR);
        return 0;
    }
    param->type = V_ASN1_SEQUENCE;

    if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_HSS),
                               V_ASN1_SEQUENCE, param, penc, penclen)) {
        return 1;
    }

    HSSerr(HSS_F_HSS_PKEY_PUB_ENCODE, HSS_R_X509_ENCODE_ERROR);
    OPENSSL_free(penc);
    ASN1_STRING_free(param);
    return 0;
}

static int hss_pkey_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if ((b->pkey.hss->pub_key == NULL)
        || (a->pkey.hss->pub_key == NULL)
        || (ASN1_OCTET_STRING_cmp(b->pkey.hss->pub_key, a->pkey.hss->pub_key) != 0)) {
        // This is returning false, not an error.
        return 0;
    } else {
        return 1;
    }
}

static int hss_pkey_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
    (void) ctx;
    return do_hss_print(bp, pkey->pkey.hss, indent, 1);
}

// Size used to allocate buffers
static int hss_pkey_size(const EVP_PKEY *pkey)
{
    return (int)hss_sig_size(pkey->pkey.hss);
}

static int hss_pkey_bits(const EVP_PKEY *pkey)
{
    return 8 * (int)hss_sig_size(pkey->pkey.hss);
}

int hss_register_ameth(int nid, EVP_PKEY_ASN1_METHOD **ameth,
                        const char *pemstr, const char *info) 
{
    /* This gets freed during engine cleanup. */
    *ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
    if (!*ameth) {
        // We don't set error because HSS errors not registered yet.
        return 0;
    }

    EVP_PKEY_asn1_set_free(*ameth,
                           hss_pkey_free);

    EVP_PKEY_asn1_set_private(*ameth,
                              hss_pkey_priv_decode,
                              hss_pkey_priv_encode,
                              hss_pkey_priv_print);

    EVP_PKEY_asn1_set_param(*ameth,
                            hss_pkey_param_decode,
                            hss_pkey_param_encode,
                            hss_pkey_missing_parameters,
                            hss_pkey_copy_parameters,
                            hss_pkey_cmp_parameters,
                            hss_pkey_param_print);

    EVP_PKEY_asn1_set_public(*ameth,
                             hss_pkey_pub_decode,
                             hss_pkey_pub_encode,
                             hss_pkey_pub_cmp,
                             hss_pkey_pub_print,
                             hss_pkey_size,
                             hss_pkey_bits);

    EVP_PKEY_asn1_set_ctrl(*ameth, hss_pkey_ctrl);

    return 1;
}
