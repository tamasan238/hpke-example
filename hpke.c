#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hpke.h>

#define RCV 0
#define SND 1

int main()
{
	int ret = 0;
	int rngRet = 0;
	Hpke hpke[2];
	WC_RNG rng[2];
	const char* start_text = "this is a test";
	const char* info_text = "info";
	const char* aad_text = "aad";
	byte ciphertext[MAX_HPKE_LABEL_SZ];
	byte plaintext[MAX_HPKE_LABEL_SZ];
	word16* receiverKey = NULL;
	word16* ephemeralKey = NULL;
	uint8_t pubKey[HPKE_Npk_MAX]; /* public key */
	word16 pubKeySz = (word16)sizeof(pubKey);

	ret = wc_HpkeInit(&hpke[SND], DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
    	HPKE_AES_128_GCM, NULL); /* or HPKE_AES_256_GCM */
	ret = wc_HpkeInit(&hpke[RCV], DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
    	HPKE_AES_128_GCM, NULL); /* or HPKE_AES_256_GCM */

	if (ret != 0)
    	return ret;

	rngRet = ret = wc_InitRng(&rng[SND]);
	rngRet = ret = wc_InitRng(&rng[RCV]);

	if (ret != 0)
    	return ret;

	/* generate the keys */
	if (ret == 0)
    	ret = wc_HpkeGenerateKeyPair(&hpke[SND], (void **)&ephemeralKey, &rng[SND]);

	if (ret == 0)
    	ret = wc_HpkeGenerateKeyPair(&hpke[RCV], (void **)&receiverKey, &rng[RCV]);
	printf("%d\n", ret);
	/* seal */
	if (ret == 0)
    	ret = wc_HpkeSealBase(&hpke[SND], ephemeralKey, receiverKey,
        	(byte*)info_text, (word32)XSTRLEN(info_text),
        	(byte*)aad_text, (word32)XSTRLEN(aad_text),
        	(byte*)start_text, (word32)XSTRLEN(start_text),
        	ciphertext);

	printf("%d\n", ret);

	/* export ephemeral key */
	 if (ret == 0)
    	ret = wc_HpkeSerializePublicKey(&hpke[SND], ephemeralKey, pubKey, &pubKeySz);

	/* open with exported ephemeral key */
	if (ret == 0)
    	ret = wc_HpkeOpenBase(&hpke[RCV], receiverKey, pubKey, pubKeySz,
        	(byte*)info_text, (word32)XSTRLEN(info_text),
        	(byte*)aad_text, (word32)XSTRLEN(aad_text),
        	ciphertext, (word32)XSTRLEN(start_text),
        	plaintext);
	printf("%d\n", ret);

	if (ret == 0)
    	ret = XMEMCMP(plaintext, start_text, XSTRLEN(start_text));

	printf("%d\n", ret);

	if (ephemeralKey != NULL){
    	wc_HpkeFreeKey(&hpke[SND], DHKEM_X25519_HKDF_SHA256, ephemeralKey, NULL);
		// wc_HpkeFreeKey(&hpke[RCV], DHKEM_X25519_HKDF_SHA256, ephemeralKey, NULL);
	}

	if (receiverKey != NULL){
    	// wc_HpkeFreeKey(&hpke[SND], DHKEM_X25519_HKDF_SHA256, receiverKey, NULL);
		wc_HpkeFreeKey(&hpke[RCV], DHKEM_X25519_HKDF_SHA256, receiverKey, NULL);
	}

	if (rngRet == 0){
    	wc_FreeRng(&rng[SND]);
		wc_FreeRng(&rng[RCV]);
	}

	if (ret == 0)
  	printf("SUCCESS");
}
