#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

// Prerequisites:
// openssl genrsa -out rsa.key 2048
// openssl pkcs8 -topk8 -inform PEM -in rsa.key -outform DER -out rsa.der -nocrypt

// Compile with:
// gcc openssl_deadlock_repro.c -o openssl_deadlock_repro -lcrypto -lpthread -Wno-deprecated-declarations

const uint32_t nthreads = 8;
const uint32_t nloops = 10;
const uint64_t total = nthreads * nloops;
static volatile uint64_t decoded = 0;

uint8_t* key_buffer;
int32_t key_buffer_len;

static bool CheckKey(EVP_PKEY* key, int32_t algId, int32_t (*check_func)(EVP_PKEY_CTX*))
{
    if (algId != NID_undef && EVP_PKEY_base_id(key) != algId)
    {
        ERR_put_error(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_ALGORITHM, __FILE__, __LINE__);
        return false;
    }

    // OpenSSL 1.x does not fail when importing a key with a zero modulus. It fails at key-usage time with an
    // out-of-memory error. For RSA keys, check the modulus for zero and report an invalid key.
    // OpenSSL 3 correctly fails with with an invalid modulus error.
    if (algId == NID_rsaEncryption)
    {
        const RSA* rsa = EVP_PKEY_get0_RSA(key);

        if (rsa != NULL)
        {
            const BIGNUM* modulus = NULL;
            RSA_get0_key(rsa, &modulus, NULL, NULL);

            if (modulus != NULL && BN_is_zero(modulus))
            {
                ERR_put_error(ERR_LIB_EVP, 0, EVP_R_DECODE_ERROR, __FILE__, __LINE__);
                return false;
            }
        }
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);

    if (ctx == NULL)
    {
        // The malloc error should have already been set.
        return false;
    }

    int check = check_func(ctx);
    EVP_PKEY_CTX_free(ctx);

    // 1: Success
    // -2: The key object had no check routine available.
    if (check == 1 || check == -2)
    {
        // We need to clear for -2, doesn't hurt for 1.
        ERR_clear_error();
        return true;
    }

    return false;
}

EVP_PKEY* CryptoNative_DecodePkcs8PrivateKey(const uint8_t* buf, int32_t len, int32_t algId)
{
    assert(buf != NULL);
    assert(len > 0);

    ERR_clear_error();

    PKCS8_PRIV_KEY_INFO* p8info = d2i_PKCS8_PRIV_KEY_INFO(NULL, &buf, len);

    if (p8info == NULL)
    {
        return NULL;
    }

    EVP_PKEY* key = EVP_PKCS82PKEY(p8info);
    PKCS8_PRIV_KEY_INFO_free(p8info);

    if (key != NULL && !CheckKey(key, algId, EVP_PKEY_check))
    {
        EVP_PKEY_free(key);
        key = NULL;
    }

    return key;
}

void decode_key() {
    EVP_PKEY* key = CryptoNative_DecodePkcs8PrivateKey(key_buffer, key_buffer_len, NID_rsaEncryption);

    if (key != NULL) {
        uint64_t val = __sync_add_and_fetch(&decoded, 1);
        if (val == total) {
            printf("done\n");
            exit(0);
        }
    }
}

void* thread_func(void *arg){
    for (int i = 0; i < nloops; i++)
        decode_key();
}

pthread_t create_thread() {
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, &thread_func, NULL);
    return thread_id;
}

int main() {
    int fd = open("./rsa.der", O_RDONLY);
    key_buffer = malloc(4096);
    key_buffer_len = read(fd, key_buffer, 4096);
    close(fd);

    for (int i = 0; i < nthreads; i++)
        create_thread();

    char* s;
    scanf("%s", s);
}