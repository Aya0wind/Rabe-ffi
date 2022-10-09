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

char *rabe_master_key_to_json(const void *sec_key);

char *rabe_pub_key_to_json(const void *pub_key);

void rabe_free_json(char *json);

void rabe_free_decrypt_result(struct DecryptResult result);

void rabe_free_init_result(struct InitKeyResult result);

void rabe_free_pub_key(const void *pub_key);

void rabe_free_master_key(const void *master_key);

const void *rabe_deserialize_cp_sec_key(const char *json);

const void *rabe_deserialize_cp_cipher(const char *json);

const void *rabe_generate_cp_sec_key(const void *master_key,
                                     const char *const *attr,
                                     uintptr_t attr_len);

const void *rabe_cp_encrypt(const void *pub_key,
                            const char *policy,
                            const char *text,
                            uintptr_t text_length);

struct DecryptResult rabe_cp_decrypt(const void *cipher, const void *sec_key);

void rabe_free_cp_sec_key(const void *sec_key);

void rabe_free_cp_cipher(const void *cipher);

char *rabe_cp_sec_key_to_json(const void *sec_key);

char *rabe_cp_cipher_to_json(const void *cipher);

const void *rabe_deserialize_kp_sec_key(const char *json);

const void *rabe_deserialize_kp_cipher(const char *json);

const void *rabe_generate_kp_sec_key(const void *master_key, const char *policy);

const void *rabe_kp_encrypt(const void *pub_key,
                            const char *const *attr,
                            uintptr_t attr_len,
                            const char *text,
                            uintptr_t text_length);

struct DecryptResult rabe_kp_decrypt(const void *cipher, const void *sec_key);

void rabe_free_kp_sec_key(const void *sec_key);

void rabe_free_kp_cipher(const void *cipher);

char *rabe_kp_sec_key_to_json(const void *sec_key);

char *rabe_kp_cipher_to_json(const void *cipher);
