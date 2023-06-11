#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hpke.h>

#define PIPE_toReceiver "tmp/toReceiver"
#define PIPE_toSender "tmp/toSender"

int main()
{
	int ret = 0;
	int rngRet = 0;
	int fd;
	Hpke hpke[1];
	WC_RNG rng[1];
	const char* plaintext = "this is a test";
	const char* info_text = "info";
	const char* aad_text = "aad";
	byte ciphertext[MAX_HPKE_LABEL_SZ];
	word16* receiverKey = NULL;
	word16* ephemeralKey = NULL;
	uint8_t pubKey[HPKE_Npk_MAX];
	word16 pubKeySz = 32; //CURVE25519_KEYSIZE

	ret = wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
    	HPKE_AES_256_GCM, NULL);

	if (ret != 0)
    	return ret;

	rngRet = ret = wc_InitRng(rng);

	if (ret != 0)
    	return ret;

	/* generate the keys */
	if (ret == 0)
    	ret = wc_HpkeGenerateKeyPair(hpke, (void **)&ephemeralKey, rng);

	/* recieve reciever's pubkey*/
	if (ret == 0){
		if ((fd = open (PIPE_toSender, O_RDONLY)) == -1)
			return fd;
		while(true)
			if(read(fd, pubKey, pubKeySz)!=0)
				break;
		close(fd);
		ret = wc_HpkeDeserializePublicKey(hpke, (void **)&receiverKey, pubKey, pubKeySz);
	}

	/* seal */
	if (ret == 0)
    	ret = wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
        	(byte*)info_text, (word32)XSTRLEN(info_text),
        	(byte*)aad_text, (word32)XSTRLEN(aad_text),
        	(byte*)plaintext, (word32)XSTRLEN(plaintext),
        	ciphertext);

	/* export ephemeral key */
	 if (ret == 0)
    	ret = wc_HpkeSerializePublicKey(hpke, ephemeralKey, pubKey, &pubKeySz);
	
	/* send ephemeral key and message*/
	if (ret == 0){
		fd = open (PIPE_toReceiver, O_WRONLY);
		if (fd == -1)
			return fd;
		write(fd, pubKey, pubKeySz);
		write(fd, ciphertext, sizeof(ciphertext));
		close(fd);
	}

	if (ephemeralKey != NULL)
    	wc_HpkeFreeKey(hpke, DHKEM_X25519_HKDF_SHA256, ephemeralKey, NULL);

	if (rngRet == 0)
    	wc_FreeRng(rng);

	if (ret == 0)
  		printf("SUCCESS");
}
