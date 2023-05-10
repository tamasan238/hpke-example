#include <stdio.h>
#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hpke.h>

#define KEM     DHKEM_X25519_HKDF_SHA256
#define KDF     HKDF_SHA256
#define AEAD    HPKE_AES_256_GCM

#define RECEIVER_PUBKEY     "receiver.pub"

int writePubKey(char filename[], uint8_t key[], word16 keySz){
    FILE*   fp;
    int     ret = 0;

    if((fp = fopen(filename, "wb")) == NULL || 
        fwrite(key, 1, keySz, fp) != keySz){
        fprintf(stderr, "Failed to write %s\n", filename);
        ret =  1;
    }

    if(fp!=NULL)
        fclose(fp);
    return ret;
}

int writeCipherText(char filename[], byte cipherText[]){
    FILE*   fp;
    int     ret = 0;

    if((fp = fopen(filename, "wb")) == NULL || 
        fwrite(cipherText, 1, MAX_HPKE_LABEL_SZ, fp) != MAX_HPKE_LABEL_SZ){
        fprintf(stderr, "Failed to write %s\n", filename);
        ret =  1;
    }

    if(fp!=NULL)
        fclose(fp);
    return ret;
}

int readPubKey(unsigned char *buff){
    FILE*   fp;
    word64  sz;
    int     ret = -1;

    if((fp = fopen(RECEIVER_PUBKEY, "rb")) == NULL ||
    fseek(fp, 0, SEEK_END) != 0 || (sz = ftell(fp)) == -1){
        fprintf(stderr, "Failed to seek %s\n", RECEIVER_PUBKEY);
        goto cleanup;
    }

    rewind(fp);
    if((buff = (unsigned char*)malloc(sz)) ==NULL ||
    fread(buff, 1, sz, fp) != sz){
        fprintf(stderr, "Failed to read %s\n", RECEIVER_PUBKEY);
        goto cleanup;
    }
    
    ret = sz;

cleanup:
    if(fp!=NULL)
        fclose(fp);
    return ret;
}

int main(int argc, char *argv[]){
    int     ret = 0;
    int     rngRet = 0;
    Hpke    hpke[1];
    WC_RNG  rng[1];
    void*   ephemeralKey = NULL;
    void*   receiverKey = NULL;
    uint8_t ephemeralPubKey[HPKE_Npk_MAX];
    uint8_t receiverPubKey[HPKE_Npk_MAX];
    word16  ephemeralPubKeySz = sizeof(ephemeralPubKey);
    word16  receiverPubKeySz;

    char    id_ephemeralKey[MAX_HPKE_LABEL_SZ];
    char    id_cipherText[MAX_HPKE_LABEL_SZ];
    const char* startText = "This is a test.";
    const char* infoText= "info";   /* optional */
    const char* aadText = "aad";    /* optional */
    // byte    plainText[MAX_HPKE_LABEL_SZ];
    byte    cipherText[MAX_HPKE_LABEL_SZ];

    /* print usage */
    if(argc!=2){
        printf("usage:\n"
            "./send [message name]\n");
        return 0;
    }

    /* initialize */
    wc_HpkeInit(hpke, KEM, KDF, AEAD, NULL);
    rngRet = wc_InitRng(rng);

    XSTRLCPY(id_ephemeralKey, argv[1], MAX_HPKE_LABEL_SZ);
    XSTRLCAT(id_ephemeralKey, ".pub", MAX_HPKE_LABEL_SZ);
    XSTRLCPY(id_cipherText, argv[1], MAX_HPKE_LABEL_SZ);
    XSTRLCAT(id_cipherText, ".enc", MAX_HPKE_LABEL_SZ);

    /* set receiver's pubkey*/
    if((receiverPubKeySz = readPubKey(receiverPubKey)) == -1){
        ret = 1;
        goto exit;
    }
    wc_HpkeDeserializePublicKey(hpke, &receiverKey,
        receiverPubKey, receiverPubKeySz);

    /* generate keypair */
    wc_HpkeGenerateKeyPair(hpke, &ephemeralKey, rng);
    wc_HpkeSerializePublicKey(hpke, ephemeralKey, 
        ephemeralPubKey, &ephemeralPubKeySz);

    /* seal */
    wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
        (byte*)infoText, (word32)XSTRLEN(infoText),
        (byte*)aadText, (word32)XSTRLEN(aadText),
        (byte*)startText, (word32)XSTRLEN(startText),
        cipherText);
    if(writeCipherText(id_cipherText, cipherText) != 0){
        ret = 1;
        goto exit;
    }
    

    if(writePubKey(id_ephemeralKey, ephemeralPubKey, ephemeralPubKeySz) != 0){
        ret = 1;
        goto exit;
    }

exit:
    /* finalize */
    if(ephemeralKey != NULL)
        wc_HpkeFreeKey(hpke, hpke->kem, ephemeralKey, NULL);
    if(rngRet == 0)
        wc_FreeRng(rng);

    return ret;
}