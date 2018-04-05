DIR=qs_sig
TOP=../..
CC=cc
INCLUDES= -I../../include
CFLAG=-g
MAKEFILE= Makefile
AR= ar r
CFLAGS= $(INCLUDES) $(CFLAG)
LIB=$(TOP)/libcrypto.a

LIBSRC= hss_ameth.c qs_sig_engine.c hss_ossl.c hss_pmeth.c hash-sigs/hss.c hash-sigs/hss_alloc.c hash-sigs/hss_aux.c hash-sigs/hss_common.c hash-sigs/hss_compute.c hash-sigs/hss_generate.c hash-sigs/hss_keygen.c hash-sigs/hss_param.c hash-sigs/hss_reserve.c hash-sigs/hss_sign.c hash-sigs/hss_sign_inc.c hash-sigs/hss_thread_single.c hash-sigs/hss_thread_pthread.c hash-sigs/hss_verify.c hash-sigs/hss_verify_inc.c hash-sigs/hss_derive.c hash-sigs/hss_zeroize.c hash-sigs/lm_common.c hash-sigs/lm_ots_common.c hash-sigs/lm_ots_sign.c hash-sigs/lm_ots_verify.c hash-sigs/lm_verify.c hash-sigs/endian.c hash-sigs/hash.c hash-sigs/hss_sha256.c

LIBOBJ= e_hss_err.o hss_ameth.o qs_sig_engine.o hss_ossl.o hss_pmeth.o hash-sigs/hss.o hash-sigs/hss_alloc.o hash-sigs/hss_aux.o hash-sigs/hss_common.o hash-sigs/hss_compute.o hash-sigs/hss_generate.o hash-sigs/hss_keygen.o hash-sigs/hss_param.o hash-sigs/hss_reserve.o hash-sigs/hss_sign.o hash-sigs/hss_sign_inc.o hash-sigs/hss_thread_single.o hash-sigs/hss_thread_pthread.o hash-sigs/hss_verify.o hash-sigs/hss_verify_inc.o hash-sigs/hss_derive.o hash-sigs/hss_zeroize.o hash-sigs/lm_common.o hash-sigs/lm_ots_common.o hash-sigs/lm_ots_sign.o hash-sigs/lm_ots_verify.o hash-sigs/lm_verify.o hash-sigs/endian.o hash-sigs/hash.o hash-sigs/hss_sha256.o

SRC=$(LIBSRC)

LIBNAME=qs_sig

top: 
	(cd $(TOP); $(MAKE) DIRS=engines EDIRS=$(DIR) sub_all)

all: lib

tags:
	ctags $(SRC)

errors:
	$(PERL) ../../util/mkerr.pl -conf hss.ec -nostatic -write $(SRC)

lib: $(LIBOBJ)
	if [ -n "$(SHARED_LIBS)" ]; then \
		$(MAKE) -f $(TOP)/Makefile.shared -e \
			LIBNAME=$(LIBNAME) \
			LIBEXTRAS='$(LIBOBJ)' \
			LIBDEPS="-L$(TOP) -lcrypto -lpthread $(EX_LIBS)" \
			link_o.$(SHLIB_TARGET); \
	else \
		$(AR) $(LIB) $(LIBOBJ); \
	fi
	@touch lib

install:
	[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		echo installing $(LIBNAME); \
		pfx=lib; \
		if expr "$(PLATFORM)" : "Cygwin" >/dev/null; then \
			sfx=".so"; \
			cp cyg$(LIBNAME).dll $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		else \
			case "$(CFLAGS)" in \
			*DSO_BEOS*) sfx=".so";; \
			*DSO_DLFCN*) sfx=`expr "$(SHLIB_EXT)" : '.*\(\.[a-z][a-z]*\)' \| ".so"`;; \
			*DSO_DL*) sfx=".sl";; \
			*DSO_WIN32*) sfx="eay32.dll"; pfx=;; \
			*) sfx=".bad";; \
			esac; \
			cp $${pfx}$(LIBNAME)$$sfx $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		fi; \
		chmod 555 $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx; \
	fi

links:

tests:

update: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi

depend: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi
local_depend:
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o hash-sigs/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff *.so *.sl *.dll

# DO NOT DELETE THIS LINE -- make depend depends on it.

endian.o: endian.c hash-sigs/endian.c hash-sigs/endian.h
hash.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
hash.o: ../../include/openssl/sha.h hash-sigs/hash.c hash-sigs/hash.h
hash.o: hash-sigs/hss_zeroize.h hash-sigs/sha256.h hash.c
hss.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
hss.o: ../../include/openssl/sha.h hash-sigs/common_defs.h hash-sigs/endian.h
hss.o: hash-sigs/hash.h hash-sigs/hss.c hash-sigs/hss.h hash-sigs/hss_aux.h
hss.o: hash-sigs/hss_common.h hash-sigs/hss_derive.h hash-sigs/hss_internal.h
hss.o: hash-sigs/hss_verify.h hash-sigs/hss_zeroize.h hash-sigs/sha256.h hss.c
hss_alloc.o: hash-sigs/common_defs.h hash-sigs/hss.h hash-sigs/hss_alloc.c
hss_alloc.o: hash-sigs/hss_common.h hash-sigs/hss_internal.h
hss_alloc.o: hash-sigs/hss_verify.h hash-sigs/hss_zeroize.h
hss_alloc.o: hash-sigs/lm_common.h hss_alloc.c
hss_ameth.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
hss_ameth.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
hss_ameth.o: ../../include/openssl/cms.h ../../include/openssl/crypto.h
hss_ameth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
hss_ameth.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
hss_ameth.o: ../../include/openssl/evp.h ../../include/openssl/hss.h
hss_ameth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
hss_ameth.o: ../../include/openssl/objects.h
hss_ameth.o: ../../include/openssl/opensslconf.h
hss_ameth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hss_ameth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
hss_ameth.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
hss_ameth.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
hss_ameth.o: ../../include/openssl/x509_vfy.h hash-sigs/common_defs.h
hss_ameth.o: hash-sigs/hss.h hash-sigs/hss_common.h hash-sigs/hss_verify.h
hss_ameth.o: hss_ameth.c hss_err.h qs_sig_engine.h
hss_aux.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
hss_aux.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
hss_aux.o: hash-sigs/endian.h hash-sigs/hash.h hash-sigs/hss.h
hss_aux.o: hash-sigs/hss_aux.c hash-sigs/hss_aux.h hash-sigs/hss_common.h
hss_aux.o: hash-sigs/hss_internal.h hash-sigs/hss_verify.h
hss_aux.o: hash-sigs/hss_zeroize.h hash-sigs/lm_common.h hash-sigs/sha256.h
hss_aux.o: hss_aux.c
hss_common.o: hash-sigs/common_defs.h hash-sigs/hss_common.c
hss_common.o: hash-sigs/hss_common.h hash-sigs/lm_common.h hss_common.c
hss_compute.o: ../../include/openssl/e_os2.h
hss_compute.o: ../../include/openssl/opensslconf.h ../../include/openssl/sha.h
hss_compute.o: hash-sigs/common_defs.h hash-sigs/endian.h hash-sigs/hash.h
hss_compute.o: hash-sigs/hss.h hash-sigs/hss_common.h hash-sigs/hss_compute.c
hss_compute.o: hash-sigs/hss_derive.h hash-sigs/hss_internal.h
hss_compute.o: hash-sigs/hss_thread.h hash-sigs/hss_verify.h
hss_compute.o: hash-sigs/hss_zeroize.h hash-sigs/lm_ots.h
hss_compute.o: hash-sigs/lm_ots_common.h hash-sigs/lm_ots_verify.h
hss_compute.o: hash-sigs/sha256.h hss_compute.c
hss_derive.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
hss_derive.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
hss_derive.o: hash-sigs/endian.h hash-sigs/hash.h hash-sigs/hss.h
hss_derive.o: hash-sigs/hss_common.h hash-sigs/hss_derive.c
hss_derive.o: hash-sigs/hss_derive.h hash-sigs/hss_internal.h
hss_derive.o: hash-sigs/hss_verify.h hash-sigs/hss_zeroize.h
hss_derive.o: hash-sigs/lm_common.h hash-sigs/lm_ots_common.h
hss_derive.o: hash-sigs/sha256.h hss_derive.c
hss_generate.o: ../../include/openssl/e_os2.h
hss_generate.o: ../../include/openssl/opensslconf.h ../../include/openssl/sha.h
hss_generate.o: hash-sigs/common_defs.h hash-sigs/endian.h hash-sigs/hash.h
hss_generate.o: hash-sigs/hss.h hash-sigs/hss_aux.h hash-sigs/hss_common.h
hss_generate.o: hash-sigs/hss_generate.c hash-sigs/hss_internal.h
hss_generate.o: hash-sigs/hss_reserve.h hash-sigs/hss_thread.h
hss_generate.o: hash-sigs/hss_verify.h hash-sigs/hss_zeroize.h
hss_generate.o: hash-sigs/lm_ots_common.h hash-sigs/sha256.h hss_generate.c
hss_keygen.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
hss_keygen.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
hss_keygen.o: hash-sigs/endian.h hash-sigs/hash.h hash-sigs/hss.h
hss_keygen.o: hash-sigs/hss_aux.h hash-sigs/hss_common.h
hss_keygen.o: hash-sigs/hss_internal.h hash-sigs/hss_keygen.c
hss_keygen.o: hash-sigs/hss_thread.h hash-sigs/hss_verify.h
hss_keygen.o: hash-sigs/hss_zeroize.h hash-sigs/lm_common.h
hss_keygen.o: hash-sigs/lm_ots_common.h hash-sigs/sha256.h hss_keygen.c
hss_ossl.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
hss_ossl.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
hss_ossl.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
hss_ossl.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
hss_ossl.o: ../../include/openssl/ecdsa.h ../../include/openssl/evp.h
hss_ossl.o: ../../include/openssl/hss.h ../../include/openssl/lhash.h
hss_ossl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
hss_ossl.o: ../../include/openssl/opensslconf.h
hss_ossl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hss_ossl.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
hss_ossl.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
hss_ossl.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
hss_ossl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
hss_ossl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
hss_ossl.o: hash-sigs/common_defs.h hash-sigs/hss.h hash-sigs/hss_common.h
hss_ossl.o: hash-sigs/hss_verify.h hss_err.h hss_ossl.c qs_sig_engine.h
hss_param.o: hash-sigs/common_defs.h hash-sigs/endian.h hash-sigs/hss.h
hss_param.o: hash-sigs/hss_common.h hash-sigs/hss_internal.h
hss_param.o: hash-sigs/hss_param.c hash-sigs/hss_verify.h
hss_param.o: hash-sigs/hss_zeroize.h hss_param.c
hss_pmeth.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
hss_pmeth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
hss_pmeth.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
hss_pmeth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
hss_pmeth.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
hss_pmeth.o: ../../include/openssl/evp.h ../../include/openssl/hss.h
hss_pmeth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
hss_pmeth.o: ../../include/openssl/objects.h
hss_pmeth.o: ../../include/openssl/opensslconf.h
hss_pmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hss_pmeth.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
hss_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
hss_pmeth.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
hss_pmeth.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
hss_pmeth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
hss_pmeth.o: hash-sigs/common_defs.h hash-sigs/hss.h hash-sigs/hss_common.h
hss_pmeth.o: hash-sigs/hss_verify.h hss_err.h hss_pmeth.c qs_sig_engine.h
hss_reserve.o: hash-sigs/common_defs.h hash-sigs/endian.h hash-sigs/hss.h
hss_reserve.o: hash-sigs/hss_common.h hash-sigs/hss_internal.h
hss_reserve.o: hash-sigs/hss_reserve.c hash-sigs/hss_reserve.h
hss_reserve.o: hash-sigs/hss_verify.h hash-sigs/hss_zeroize.h hss_reserve.c
hss_sha256.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
hss_sha256.o: ../../include/openssl/sha.h hash-sigs/endian.h
hss_sha256.o: hash-sigs/hss_sha256.c hash-sigs/sha256.h hss_sha256.c
hss_sign.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
hss_sign.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
hss_sign.o: hash-sigs/endian.h hash-sigs/hash.h hash-sigs/hss.h
hss_sign.o: hash-sigs/hss_aux.h hash-sigs/hss_common.h hash-sigs/hss_derive.h
hss_sign.o: hash-sigs/hss_internal.h hash-sigs/hss_reserve.h
hss_sign.o: hash-sigs/hss_sign.c hash-sigs/hss_thread.h hash-sigs/hss_verify.h
hss_sign.o: hash-sigs/hss_zeroize.h hash-sigs/lm_ots.h
hss_sign.o: hash-sigs/lm_ots_common.h hash-sigs/lm_ots_verify.h
hss_sign.o: hash-sigs/sha256.h hss_sign.c
hss_sign_inc.o: ../../include/openssl/e_os2.h
hss_sign_inc.o: ../../include/openssl/opensslconf.h ../../include/openssl/sha.h
hss_sign_inc.o: hash-sigs/common_defs.h hash-sigs/endian.h hash-sigs/hash.h
hss_sign_inc.o: hash-sigs/hss.h hash-sigs/hss_common.h hash-sigs/hss_derive.h
hss_sign_inc.o: hash-sigs/hss_internal.h hash-sigs/hss_sign_inc.c
hss_sign_inc.o: hash-sigs/hss_sign_inc.h hash-sigs/hss_verify.h
hss_sign_inc.o: hash-sigs/hss_verify_inc.h hash-sigs/hss_zeroize.h
hss_sign_inc.o: hash-sigs/lm_common.h hash-sigs/lm_ots.h
hss_sign_inc.o: hash-sigs/lm_ots_common.h hash-sigs/lm_ots_verify.h
hss_sign_inc.o: hash-sigs/lm_verify.h hash-sigs/sha256.h hss_sign_inc.c
hss_thread_pthread.o: ../../include/openssl/e_os2.h
hss_thread_pthread.o: ../../include/openssl/opensslconf.h
hss_thread_pthread.o: hash-sigs/../../../e_os.h hash-sigs/hss_thread.h
hss_thread_pthread.o: hash-sigs/hss_thread_pthread.c hss_thread_pthread.c
hss_thread_single.o: ../../include/openssl/e_os2.h
hss_thread_single.o: ../../include/openssl/opensslconf.h
hss_thread_single.o: hash-sigs/../../../e_os.h hash-sigs/hss_thread.h
hss_thread_single.o: hash-sigs/hss_thread_single.c hss_thread_single.c
hss_verify.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
hss_verify.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
hss_verify.o: hash-sigs/endian.h hash-sigs/hash.h hash-sigs/hss.h
hss_verify.o: hash-sigs/hss_common.h hash-sigs/hss_internal.h
hss_verify.o: hash-sigs/hss_thread.h hash-sigs/hss_verify.c
hss_verify.o: hash-sigs/hss_verify.h hash-sigs/hss_zeroize.h
hss_verify.o: hash-sigs/lm_common.h hash-sigs/lm_ots_verify.h
hss_verify.o: hash-sigs/lm_verify.h hash-sigs/sha256.h hss_verify.c
hss_verify_inc.o: ../../include/openssl/e_os2.h
hss_verify_inc.o: ../../include/openssl/opensslconf.h
hss_verify_inc.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
hss_verify_inc.o: hash-sigs/endian.h hash-sigs/hash.h hash-sigs/hss.h
hss_verify_inc.o: hash-sigs/hss_common.h hash-sigs/hss_internal.h
hss_verify_inc.o: hash-sigs/hss_thread.h hash-sigs/hss_verify.h
hss_verify_inc.o: hash-sigs/hss_verify_inc.c hash-sigs/hss_verify_inc.h
hss_verify_inc.o: hash-sigs/hss_zeroize.h hash-sigs/lm_common.h
hss_verify_inc.o: hash-sigs/lm_ots_common.h hash-sigs/lm_ots_verify.h
hss_verify_inc.o: hash-sigs/lm_verify.h hash-sigs/sha256.h hss_verify_inc.c
hss_zeroize.o: hash-sigs/hss_zeroize.c hash-sigs/hss_zeroize.h hss_zeroize.c
lm_common.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
lm_common.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
lm_common.o: hash-sigs/hash.h hash-sigs/lm_common.c hash-sigs/lm_common.h
lm_common.o: hash-sigs/lm_ots_common.h hash-sigs/sha256.h lm_common.c
lm_ots_common.o: ../../include/openssl/e_os2.h
lm_ots_common.o: ../../include/openssl/opensslconf.h
lm_ots_common.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
lm_ots_common.o: hash-sigs/hash.h hash-sigs/lm_ots_common.c
lm_ots_common.o: hash-sigs/lm_ots_common.h hash-sigs/sha256.h lm_ots_common.c
lm_ots_sign.o: ../../include/openssl/e_os2.h
lm_ots_sign.o: ../../include/openssl/opensslconf.h ../../include/openssl/sha.h
lm_ots_sign.o: hash-sigs/common_defs.h hash-sigs/endian.h hash-sigs/hash.h
lm_ots_sign.o: hash-sigs/hss.h hash-sigs/hss_common.h hash-sigs/hss_derive.h
lm_ots_sign.o: hash-sigs/hss_internal.h hash-sigs/hss_verify.h
lm_ots_sign.o: hash-sigs/hss_zeroize.h hash-sigs/lm_ots.h
lm_ots_sign.o: hash-sigs/lm_ots_common.h hash-sigs/lm_ots_sign.c
lm_ots_sign.o: hash-sigs/lm_ots_verify.h hash-sigs/sha256.h lm_ots_sign.c
lm_ots_verify.o: ../../include/openssl/e_os2.h
lm_ots_verify.o: ../../include/openssl/opensslconf.h
lm_ots_verify.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
lm_ots_verify.o: hash-sigs/endian.h hash-sigs/hash.h hash-sigs/lm_ots_common.h
lm_ots_verify.o: hash-sigs/lm_ots_verify.c hash-sigs/lm_ots_verify.h
lm_ots_verify.o: hash-sigs/sha256.h lm_ots_verify.c
lm_verify.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
lm_verify.o: ../../include/openssl/sha.h hash-sigs/common_defs.h
lm_verify.o: hash-sigs/endian.h hash-sigs/hash.h hash-sigs/lm_common.h
lm_verify.o: hash-sigs/lm_ots_common.h hash-sigs/lm_ots_verify.h
lm_verify.o: hash-sigs/lm_verify.c hash-sigs/lm_verify.h hash-sigs/sha256.h
lm_verify.o: lm_verify.c
qs_sig_engine.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
qs_sig_engine.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
qs_sig_engine.o: ../../include/openssl/cms.h ../../include/openssl/crypto.h
qs_sig_engine.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
qs_sig_engine.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
qs_sig_engine.o: ../../include/openssl/engine.h ../../include/openssl/err.h
qs_sig_engine.o: ../../include/openssl/evp.h ../../include/openssl/hss.h
qs_sig_engine.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
qs_sig_engine.o: ../../include/openssl/objects.h
qs_sig_engine.o: ../../include/openssl/opensslconf.h
qs_sig_engine.o: ../../include/openssl/opensslv.h
qs_sig_engine.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
qs_sig_engine.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
qs_sig_engine.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
qs_sig_engine.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
qs_sig_engine.o: hss_err.h qs_sig_engine.c qs_sig_engine.h
