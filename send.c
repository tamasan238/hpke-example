#include "common.h"

int main()
{
    int ret = 0;
    int rngRet = 0;
    int fd;
    Hpke hpke[1];
    WC_RNG rng[1];
    const char *info_text = INFO_TXT;
    const char *aad_text = AAD_TXT;
    byte ciphertext[MAX_HPKE_LABEL_SZ];
    char plaintext[MAX_HPKE_LABEL_SZ];
    word32 plaintextSz;

    word16 *receiverKey = NULL;
    word16 *ephemeralKey = NULL;
    uint8_t pubKey[HPKE_Npk_MAX];
    word16 pubKeySz = 0;

    ret = wc_HpkeInit(hpke, KEM, KDF, AEAD, NULL);

    if (ret == 0)
        rngRet = ret = wc_InitRng(rng);

    /* generate ephemeral keys */
    if (ret == 0)
        ret = wc_HpkeGenerateKeyPair(hpke, (void **)&ephemeralKey, rng);

    /* recieve reciever's pubkey */
    if (ret == 0)
    {
        if ((fd = open(PIPE_toSender, O_RDONLY)) == -1)
            return fd;
        read(fd, &pubKeySz, sizeof(word16));
        read(fd, pubKey, pubKeySz);
        close(fd);
    }

    /* load receiver's pubkey */
    if (ret == 0)
    {
        ret = wc_HpkeDeserializePublicKey(hpke, (void **)&receiverKey, pubKey, pubKeySz);
        scanf("%s", plaintext);
        plaintextSz = XSTRLEN(plaintext);
    }

    /* seal */
    if (ret == 0)
        ret = wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
                              (byte *)info_text, (word32)XSTRLEN(info_text),
                              (byte *)aad_text, (word32)XSTRLEN(aad_text),
                              (byte *)plaintext, plaintextSz,
                              ciphertext);

    /* export ephemeral pubkey */
    if (ret == 0)
        ret = wc_HpkeSerializePublicKey(hpke, ephemeralKey, pubKey, &pubKeySz);

    /* send ephemeral pubkey and message*/
    if (ret == 0)
    {
        if ((fd = open(PIPE_toReceiver, O_WRONLY)) == -1)
            return fd;
        write(fd, &pubKeySz, sizeof(pubKeySz));
        write(fd, pubKey, pubKeySz);
        write(fd, &plaintextSz, sizeof(plaintextSz));
        write(fd, ciphertext, sizeof(ciphertext));
        close(fd);
    }

    if (ephemeralKey != NULL)
        wc_HpkeFreeKey(hpke, KEM, ephemeralKey, NULL);

    if (rngRet == 0)
        wc_FreeRng(rng);

    if (ret == 0)
        printf("SUCCESS");

    return ret;
}
