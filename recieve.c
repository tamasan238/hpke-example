#include <stdio.h>
#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hpke.h>

#define KEM     DHKEM_X25519_HKDF_SHA256
#define KDF     HKDF_SHA256
#define AEAD    HPKE_AES_256_GCM

#define EPHEMERAL_PUBKEY    "ephemeral.pub"
#define RECIEVER_PUBKEY     "reciever.pub"
#define CIPHER_TEXT         "cipher_text.dat"

int writePubKey(uint8_t key[], word16 keySz){
    FILE* fp;
    int ret = 0;

    if((fp = fopen(RECIEVER_PUBKEY, "wb")) == NULL ||
    fwrite(key, 1, keySz, fp) != keySz){
        fprintf(stderr, "Failed to write %s\n", RECIEVER_PUBKEY);
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

    if((fp = fopen(EPHEMERAL_PUBKEY, "rb")) == NULL ||
    fseek(fp, 0, SEEK_END) != 0 || (sz = ftell(fp)) == -1){
        fprintf(stderr, "Failed to seek %s\n", EPHEMERAL_PUBKEY);
        goto cleanup;
    }

    rewind(fp);
    if((buff = (unsigned char*)malloc(sz)) ==NULL ||
    fread(buff, 1, sz, fp) != sz){
        fprintf(stderr, "Failed to read %s\n", EPHEMERAL_PUBKEY);
        goto cleanup;
    }
    
    ret = sz;

cleanup:
    if(fp!=NULL)
        fclose(fp);
    return ret;
}

int readCipherText(char *buff){
    FILE*   fp;
    int     ret = 0;

    if((fp = fopen(CIPHER_TEXT, "rb")) == NULL ||
    (buff = (char*)malloc(HPKE_Npk_MAX)) == NULL ||
    fread(buff, 1, HPKE_Npk_MAX, fp) != HPKE_Npk_MAX){
        fprintf(stderr, "Failed to read %s\n", CIPHER_TEXT);
        ret = 1;
    }

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
    void*   recieverKey;
    uint8_t ephemeralPubKey[HPKE_Npk_MAX];
    uint8_t recieverPubKey[HPKE_Npk_MAX];
    word16  ephemeralPubKeySz = sizeof(ephemeralPubKey);
    word16  recieverPubKeySz = sizeof(recieverPubKey);

    char*   plainText = NULL;
    char*   infoText = NULL;    /* optional */
    char*   aadText = "aad";    /* optional */
    char    cipherText[MAX_HPKE_LABEL_SZ];

    /* print usage */
    if(argc!=2){
        printf("usage:\n"
            "to generate keys:     ./recieve -k\n"
            "to recieve a message: ./recieve -r\n");
        return 0;
    }

    /* initialize */
    wc_HpkeInit(hpke, KEM, KDF, AEAD, NULL);
    rngRet = wc_InitRng(rng);

    /* generate keypair */
    if(XSTRCMP(argv[1], "-k")==0){
        wc_HpkeGenerateKeyPair(hpke, &recieverKey, rng);
        wc_HpkeSerializePublicKey(hpke, recieverKey, 
            recieverPubKey, &recieverPubKeySz);
        if(writePubKey(recieverPubKey, recieverPubKeySz) != 0){
            ret = 1;
            goto exit;
        }
    }

    /* recieve message */
    if(XSTRCMP(argv[1], "-r")==0){

        /* set sender's pubkey */
        if((ephemeralPubKeySz = readPubKey(ephemeralPubKey)) == -1){
            ret = 1;
            goto exit;
        }        

        /* set cipher text */
        if(readCipherText(cipherText) != 0){
            ret = 1;
            goto exit;
        }

        /* open */
        wc_HpkeOpenBase(hpke, recieverKey,
            ephemeralPubKey, ephemeralPubKeySz,
            (byte*)infoText, XSTRLEN(infoText),
            (byte*)aadText, XSTRLEN(aadText),
            (byte*)cipherText, XSTRLEN(plainText),
            (byte*)plainText);

        // todo: wc_HpkeOpenBase()実行時に発生するコアダンプの解消
        //      recieverKeyに秘密鍵が入っていないことによるものか...？
        //      exportもできないので，方針自体変えるべきか．

        // todo: plainTextの出力
    }

exit:
    /* finalize */
    if(ephemeralKey != NULL)
        wc_HpkeFreeKey(hpke, hpke->kem, ephemeralKey, NULL);
    if(rngRet == 0)
        wc_FreeRng(rng);

    return ret;
}