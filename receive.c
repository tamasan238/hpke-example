#include <stdio.h>
#include <stdint.h>
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
	const char* info_text = "info";
	const char* aad_text = "aad";
	byte ciphertext[MAX_HPKE_LABEL_SZ];
	byte plaintext[MAX_HPKE_LABEL_SZ];
	word32 plaintextSz = 0;
	word16* receiverKey = NULL;
	uint8_t pubKey[HPKE_Npk_MAX];
	word16 pubKeySz = (word16)sizeof(pubKey);

	ret = wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
    	HPKE_AES_256_GCM, NULL);

	if (ret != 0)
    	return ret;

	rngRet = ret = wc_InitRng(rng);

	if (ret != 0)
    	return ret;

	/* generate the keys */
	if (ret == 0)
    	ret = wc_HpkeGenerateKeyPair(hpke, (void **)&receiverKey, rng);

	/* export receiver key */
	if (ret == 0)
    	ret = wc_HpkeSerializePublicKey(hpke, receiverKey, pubKey, &pubKeySz);
	
	/* send reciever's pubkey*/
	if (ret == 0){
		fd = open (PIPE_toSender, O_WRONLY);
		if (fd == -1)
			return fd;
		write(fd, pubKey, pubKeySz);
		close(fd);
	}

	/* recieve ephemeral pubkey and message*/
	if (ret == 0){
		if ((fd = open (PIPE_toReceiver, O_RDONLY)) == -1)
			return fd;
		read(fd, pubKey, pubKeySz);
		read(fd, ciphertext, sizeof(ciphertext));
		read(fd, &plaintextSz, sizeof(plaintextSz));
		close(fd);
	}

	/* open with exported ephemeral key */
	if (ret == 0)
    	ret = wc_HpkeOpenBase(hpke, receiverKey, pubKey, pubKeySz,
        	(byte*)info_text, (word32)XSTRLEN(info_text),
        	(byte*)aad_text, (word32)XSTRLEN(aad_text),
			ciphertext, (word32)plaintextSz, plaintext);
	
	printf("%s\n", plaintext);

	if (receiverKey != NULL)
		wc_HpkeFreeKey(hpke, DHKEM_X25519_HKDF_SHA256, receiverKey, NULL);

	if (rngRet == 0)
		wc_FreeRng(rng);

	if (ret == 0)
  		printf("SUCCESS");
}
