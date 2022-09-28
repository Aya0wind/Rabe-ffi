#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct InitKeyResult {
  const void *pub_key;
  const void *master_key;
} InitKeyResult;

typedef struct DecryptResult {
  const unsigned char *buffer;
  uintptr_t len;
} DecryptResult;

struct InitKeyResult rabe_init(void);

const void *rabe_deserialize_pub_key(const char *json);

const void *rabe_deserialize_master_key(const char *json);

const void *rabe_deserialize_secret_key(const char *json);

const void *rabe_deserialize_ciphertext(const char *json);

const void *rabe_generate_sec_key(const void *master_key,
                                  const char *const *attr,
                                  uintptr_t attr_len);

const void *rabe_encrypt(const void *pub_key,
                         const char *policy,
                         const char *text,
                         uintptr_t text_length);

struct DecryptResult rabe_decrypt(const void *cipher, const void *sec_key);

void rabe_free_decrypt_result(struct DecryptResult result);

void rabe_free_init_result(struct InitKeyResult result);

void rabe_free_pub_key(const void *pub_key);

void rabe_free_master_key(const void *master_key);

void rabe_free_sec_key(const void *sec_key);

void rabe_free_cipher(const void *cipher);

char *rabe_master_key_to_json(const void *sec_key);

char *rabe_pub_key_to_json(const void *pub_key);

char *rabe_sec_key_to_json(const void *sec_key);

char *rabe_cipher_to_json(const void *cipher);

void rabe_free_json(char *json);
