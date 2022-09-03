# Makefile for generating test data

REF_VERSION = 20180313
REF_PKG_DIR := sphincs+-reference-implementation-$(REF_VERSION)
CRYPTO_SIGN_DIR := $(REF_PKG_DIR)/crypto_sign

TEST_RSPS := $(foreach S,128f 128s,tests/shake256-$(S)/PQCsignKAT_64.rsp)
TEST_RSPS += $(foreach S,192f 192s,tests/shake256-$(S)/PQCsignKAT_96.rsp)
TEST_RSPS += $(foreach S,256f 256s,tests/shake256-$(S)/PQCsignKAT_128.rsp)

RNG_SOURCES = tests/rng.c tests/rng.h

default: $(TEST_RSPS) $(RNG_SOURCES)

tests/shake256-%/PQCsignKAT_64.rsp: \
		$(CRYPTO_SIGN_DIR)/sphincs-shake256-%/PQCgenKAT_sign
	mkdir -p $(@D)
	cd $(@D) && ../../$<

tests/shake256-%/PQCsignKAT_96.rsp: \
		$(CRYPTO_SIGN_DIR)/sphincs-shake256-%/PQCgenKAT_sign
	mkdir -p $(@D)
	cd $(@D) && ../../$<

tests/shake256-%/PQCsignKAT_128.rsp: \
		$(CRYPTO_SIGN_DIR)/sphincs-shake256-%/PQCgenKAT_sign
	mkdir -p $(@D)
	cd $(@D) && ../../$<

$(CRYPTO_SIGN_DIR)/sphincs-shake256-%/PQCgenKAT_sign: $(REF_PKG_DIR)
	make -C $(@D)

$(RNG_SOURCES): $(REF_PKG_DIR)
	cp $</crypto_sign/sphincs-haraka-128f/$(notdir $@) $@
	git add $@

$(REF_PKG_DIR): $(REF_PKG_DIR).tar.bz2
	tar xf $<
	touch $@

$(REF_PKG_DIR).tar.bz2:
	wget https://sphincs.org/data/$@
