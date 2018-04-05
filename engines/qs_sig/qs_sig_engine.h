#ifndef HSS_ENGINE_H
#define HSS_ENGINE_H

#include <openssl/bio.h>
#include <openssl/ossl_typ.h>

/* Buffer size for pretty printing. */
#define QS_SIG_PRETTY_PRINT_LENGTH 128

/** Prints a byte array into a pretty hexadecimal string.
 *
 * @param[in]  bp         The BIO that specifies the output.
 * @param[in]  prefix     The string to be printed before the hexadecimal
 *                        output.
 * @param[in]  str        The byte array to be pretty printed.
 * @param[in]  off        The white space offset that goes before each line
 *                        of the hexadecimal output.
 *
 * @return 1 on success, 0 otherwise.
 */
int qs_sig_engine_octet_print(BIO *bp, const char *prefix, const ASN1_OCTET_STRING *str, int off);

// -------------------------------------------------------------------------------------------------
// EVP Registration and Cleanup.
// -------------------------------------------------------------------------------------------------

/** Register the callbacks for doing ASN.1 related stuff for the engine's HSS
 * algorithm.
 *
 * The set of callbacks that are registered are related to pubic keys, private
 * keys and parameters.
 *
 * They allow for decoding, encoding and printing the private key.  They allow
 * for  decoding, encoding, comparing, printing and finding the size of the
 * public keys. They allow decoding, encoding, comparing, printing and copying
 * of the parameters.
 *
 * @param[in]   nid    The NID of HSS (for example, @c NID_hss).
 * @param[out]  ameth  A variable to receive the instance of
 *                     @c EVP_PKEY_ASN1_METHOD.
 * @param[in]   pemstr This is a short string to describe the algorithm.
 *                     Typically this would be "HSS".
 * @param[in]   info   This is a longer more descriptive string that might
 *                     be used to identify the algorithm.
 *
 * @return 1 on success, 0 otherwise.
 */
int hss_register_ameth(int nid, EVP_PKEY_ASN1_METHOD **ameth,
                            const char *pemstr, const char *info);

/** Register the callbacks for doing PMETH related stuff for the engine's HSS
 * algorithm.
 *
 * The set of callbacks that are registered are only related to and required
 * for public key cryptography signing and authenticating.
 *
 * They are for pkey initialization, parameter setting, key generation,
 * signature creation, signature verification and pkey cleanup.
 *
 * @param[in]   nid    The NID of HSS (for example, @c NID_hss).
 * @param[out]  pmeth  A variable to receive the instance of
 *                     @c EVP_PKEY_METHOD.
 * @param       flags  Ignored.  Reserved for future use.
 *
 * @return 1 on success, 0 otherwise.
 */
int hss_register_pmeth(int nid, EVP_PKEY_METHOD **pmeth, int flags);

// -------------------------------------------------------------------------------------------------
// Direct Toolkit Interfacing Code to be Implemented in hss_ossl.c.
// -------------------------------------------------------------------------------------------------


/** Generates an HSS public and private key pair.
 *
 * Uses the following information from the @a hss parameter to create the key
 * pair and write all of the private key to file(s):
 *
 * * winternitz_value
 * * tree_height
 *
 * Sets the following information in the @a hss parameter:
 *
 * - pub_key
 * - priv_key
 *
 * @param[in,out] hss    See the description.
 *
 * @return 1 on success, 0 otherwise.
 */
int hss_keygen(HSS *hss);

/** Give the required signature buffer size or sign the digest.
 *
 * If @a sig is @c NULL write the required signature buffer size to @a siglen.
 *
 * Otherwise, using the private key @a priv to sign the digest that @a dgst
 * points to and put the resulting signature in @a sig.
 *
 * @param[in]      pkey    The HSS pkey.
 * @param[in]      dgst    Digest to be signed.
 * @param[in]      dlen    The length of the digest.
 * @param[in,out]  sig     @c NULL indicates signature need not be produced.
 *                         Otherwise, pointer to buffer where signature is to
 *                         be written.
 * @param[in,out]  siglen  Length of the signature output buffer.
 *
 * @return 1 on success, 0 otherwise.
 */
int hss_sign(EVP_PKEY *pkey,
                  const unsigned char *dgst, const size_t dlen,
                  unsigned char *sig, size_t *siglen);

/** Verify a signature against a digest.
 *
 * Using the private key and parameters in @a hss, verify that the signature in
 * @a sig was created by signing the digest in @a dgst.
 *
 * @param[in]  hss     The struct containing the public key and parameters.
 * @param[in]  dgst    Digest to be verified.
 * @param[in]  dlen    The length of the digest.
 * @param[in]  sig     Pointer to buffer containing the signature.
 * @param[in]  siglen  Length of the signature buffer.
 *
 * @return 1 on successful verification, 0 on incorrect signature, -1 on error.
 */
int hss_verify(HSS *hss, const unsigned char *dgst, size_t dlen,
                    const unsigned char *sig, size_t siglen);

/** Calculate the signature size.
 *
 * Using the parameters in @a hss, return the size of the HSS signature that
 * would be produced when signing a digest.
 *
 * @param[in]  The struct containing the parameters.
 *
 * @return size of the signature or 0 on failure.
 */
size_t hss_sig_size(const HSS *r);

/** Load HSS working key in the engine.
 *
 * Using the private key @a hss, load the working key (a potentially slow
 * operation) which may be used multiple times later (making these operations
 * faster).
 *
 * @param[in]  hss     The struct containing the private key.
 *
 * @return 1 on successful load, 0 otherwise.
 */
int hss_load_working_key(HSS *hss);

#endif /* HSS_ENGINE_H */
