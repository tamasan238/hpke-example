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
    byte plaintext[MAX_HPKE_LABEL_SZ];
    word32 plaintextSz = 0;

    word16 *receiverKey = NULL;
    uint8_t pubKey[HPKE_Npk_MAX];
    word16 pubKeySz = (word16)sizeof(pubKey);

    ret = wc_HpkeInit(hpke, KEM, KDF, AEAD, NULL);

    if (ret == 0)
        rngRet = ret = wc_InitRng(rng);

    /* generate receiver's keys */
    if (ret == 0)
        ret = wc_HpkeGenerateKeyPair(hpke, (void **)&receiverKey, rng);

    /* export receiver's pubkey */
    if (ret == 0)
        ret = wc_HpkeSerializePublicKey(hpke, receiverKey, pubKey, &pubKeySz);

    /* send reciever's pubkey */
    if (ret == 0)
    {
        if ((fd = open(PIPE_toSender, O_WRONLY)) == -1)
            return fd;
        write(fd, &pubKeySz, sizeof(pubKeySz));
        write(fd, pubKey, pubKeySz);
        close(fd);
    }

    /* recieve ephemeral pubkey and message*/
    if (ret == 0)
    {
        if ((fd = open(PIPE_toReceiver, O_RDONLY)) == -1)
            return fd;
        read(fd, &pubKeySz, sizeof(word16));
        read(fd, pubKey, pubKeySz);
        read(fd, &plaintextSz, sizeof(plaintextSz));
        read(fd, ciphertext, sizeof(ciphertext));
        close(fd);
    }

    /* open with exported ephemeral pubkey */
    if (ret == 0)
    {
        ret = wc_HpkeOpenBase(hpke, receiverKey, pubKey, pubKeySz,
                              (byte *)info_text, (word32)XSTRLEN(info_text),
                              (byte *)aad_text, (word32)XSTRLEN(aad_text),
                              ciphertext, (word32)plaintextSz, plaintext);
        printf("%s\n", plaintext);
    }

    if (receiverKey != NULL)
        wc_HpkeFreeKey(hpke, KEM, receiverKey, NULL);

    if (rngRet == 0)
        wc_FreeRng(rng);

    if (ret == 0)
        printf("SUCCESS");

    return ret;
}
