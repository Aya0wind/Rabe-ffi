#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct CBoxedBuffer {
  const unsigned char *buffer;
  unsigned int len;
} CBoxedBuffer;

typedef struct Ac17SetupResult {
  const void *master_key;
  const void *public_key;
} Ac17SetupResult;

typedef struct Aw11AuthGenResult {
  const void *master_key;
  const void *public_key;
} Aw11AuthGenResult;

typedef struct BdabeSetupResult {
  const void *master_key;
  const void *public_key;
} BdabeSetupResult;

typedef struct BswSetupResult {
  const void *master_key;
  const void *public_key;
} BswSetupResult;

typedef struct Mke08SetupResult {
  const void *master_key;
  const void *public_key;
} Mke08SetupResult;

typedef struct Yct14AbeSetupResult {
  const void *master_key;
  const void *public_key;
} Yct14AbeSetupResult;

typedef struct LswSetupResult {
  const void *master_key;
  const void *public_key;
} LswSetupResult;

void rabe_free_json(char *json);

const char *rabe_get_thread_last_error(void);

void rabe_free_boxed_buffer(struct CBoxedBuffer result);

struct Ac17SetupResult rabe_ac17_init(void);

const void *rabe_cp_ac17_generate_secret_key(const void *master_key,
                                             const char *const *attr,
                                             uintptr_t attr_len);

const void *rabe_cp_ac17_encrypt(const void *public_key, const char *policy,
                                 const char *text, uintptr_t text_length);

struct CBoxedBuffer rabe_cp_ac17_decrypt(const void *cipher,
                                         const void *secret_key);

char *rabe_ac17_master_key_to_json(const void *ptr);

char *rabe_ac17_public_key_to_json(const void *ptr);

char *rabe_cp_ac17_secret_key_to_json(const void *ptr);

char *rabe_cp_ac17_cipher_to_json(const void *ptr);

const void *rabe_ac17_master_key_from_json(const char *json);

const void *rabe_ac17_public_key_from_json(const char *json);

const void *rabe_cp_ac17_secret_key_from_json(const char *json);

const void *rabe_cp_ac17_cipher_from_json(const char *json);

void rabe_ac17_free_master_key(const void *ptr);

void rabe_ac17_free_public_key(const void *ptr);

void rabe_cp_ac17_free_secret_key(const void *ptr);

void rabe_cp_ac17_free_cipher(const void *ptr);

const void *rabe_aw11_init(void);

struct Aw11AuthGenResult rabe_cp_aw11_generate_auth(const void *global_key,
                                                    const char *const *attrs,
                                                    uintptr_t attr_len);

const void *rabe_cp_aw11_generate_secret_key(const void *global_key,
                                             const void *master_key,
                                             const char *name,
                                             const char *const *attrs,
                                             uintptr_t attr_len);

const void *rabe_cp_aw11_encrypt(const void *global_key,
                                 const void *const *public_keys,
                                 uintptr_t public_keys_len, const char *policy,
                                 const char *text, uintptr_t text_length);

struct CBoxedBuffer rabe_cp_aw11_decrypt(const void *global_key,
                                         const void *secret_key,
                                         const void *cipher);

const void *rabe_cp_aw11_master_key_from_json(const char *json);

const void *rabe_cp_aw11_public_key_from_json(const char *json);

const void *rabe_cp_aw11_secret_key_from_json(const char *json);

const void *rabe_cp_aw11_ciphertext_from_json(const char *json);

const void *rabe_cp_aw11_global_key_from_json(const char *json);

char *rabe_cp_aw11_master_key_to_json(const void *ptr);

char *rabe_cp_aw11_public_key_to_json(const void *ptr);

char *rabe_cp_aw11_secret_key_to_json(const void *ptr);

char *rabe_cp_aw11_ciphertext_to_json(const void *ptr);

char *rabe_cp_aw11_global_key_to_json(const void *ptr);

void rabe_cp_aw11_free_master_key(const void *ptr);

void rabe_cp_aw11_free_public_key(const void *ptr);

void rabe_cp_aw11_free_secret_key(const void *ptr);

void rabe_cp_aw11_free_ciphertext(const void *ptr);

void rabe_cp_aw11_free_global_key(const void *ptr);

struct BdabeSetupResult rabe_cp_bdabe_init(void);

const void *rabe_cp_bdabe_generate_secret_authority_key(const void *public_key,
                                                        const void *master_key,
                                                        const char *name);

const void *
rabe_cp_bdabe_generate_secret_attribute_key(const void *public_user_key,
                                            const void *secret_authority_key,
                                            const char *attr);

const void *rabe_cp_bdabe_generate_user_key(const void *public_key,
                                            const void *secret_authority_key,
                                            const char *name);

const void *rabe_cp_bdabe_generate_public_attribute_key(
    const void *public_key, const void *secret_authority_key, const char *name);

int rabe_cp_bdabe_add_attribute_to_user_key(const void *secret_authority_key,
                                            const void *user_key,
                                            const char *attr);

const void *rabe_cp_bdabe_encrypt(const void *public_key,
                                  const void *const *public_attribute_keys,
                                  uintptr_t public_attribute_keys_len,
                                  const char *policy, const char *text,
                                  uintptr_t text_length);

struct CBoxedBuffer rabe_cp_bdabe_decrypt(const void *public_key,
                                          const void *user_key,
                                          const void *cipher);

char *rabe_cp_bdabe_public_user_key_to_json(const void *ptr);

char *rabe_cp_bdabe_secret_user_key_to_json(const void *ptr);

char *rabe_cp_bdabe_master_key_to_json(const void *ptr);

char *rabe_cp_bdabe_public_key_to_json(const void *ptr);

char *rabe_cp_bdabe_secret_authority_key_to_json(const void *ptr);

char *rabe_cp_bdabe_secret_attribute_key_to_json(const void *ptr);

char *rabe_cp_bdabe_public_attribute_key_to_json(const void *ptr);

char *rabe_cp_bdabe_user_key_to_json(const void *ptr);

char *rabe_cp_bdabe_ciphertext_to_json(const void *ptr);

const void *rabe_cp_bdabe_public_user_key_from_json(const char *json);

const void *rabe_cp_bdabe_secret_user_key_from_json(const char *json);

const void *rabe_cp_bdabe_master_key_from_json(const char *json);

const void *rabe_cp_bdabe_public_key_from_json(const char *json);

const void *rabe_cp_bdabe_secret_authority_key_from_json(const char *json);

const void *rabe_cp_bdabe_secret_attribute_key_from_json(const char *json);

const void *rabe_cp_bdabe_public_attribute_key_from_json(const char *json);

const void *rabe_cp_bdabe_user_key_from_json(const char *json);

const void *rabe_cp_bdabe_ciphertext_from_json(const char *json);

void rabe_cp_bdabe_free_public_user_key(const void *ptr);

void rabe_cp_bdabe_free_secret_user_key(const void *ptr);

void rabe_cp_bdabe_free_master_key(const void *ptr);

void rabe_cp_bdabe_free_public_key(const void *ptr);

void rabe_cp_bdabe_free_secret_authority_key(const void *ptr);

void rabe_cp_bdabe_free_secret_attribute_key(const void *ptr);

void rabe_cp_bdabe_free_public_attribute_key(const void *ptr);

void rabe_cp_bdabe_free_user_key(const void *ptr);

void rabe_cp_bdabe_free_ciphertext(const void *ptr);

struct BswSetupResult rabe_bsw_init(void);

const void *rabe_cp_bsw_generate_secret_key(const void *public_key,
                                            const void *master_key,
                                            const char *const *attr,
                                            uintptr_t attr_len);

const void *rabe_cp_bsw_encrypt(const void *public_key, const char *policy,
                                const char *text, uintptr_t text_length);

struct CBoxedBuffer rabe_cp_bsw_decrypt(const void *cipher,
                                        const void *secret_key);

const void *rabe_cp_bsw_secret_key_from_json(const char *json);

const void *rabe_cp_bsw_public_key_from_json(const char *json);

const void *rabe_cp_bsw_ciphertext_from_json(const char *json);

const void *rabe_cp_bsw_master_key_from_json(const char *json);

char *rabe_cp_bsw_secret_key_to_json(const void *ptr);

char *rabe_cp_bsw_public_key_to_json(const void *ptr);

char *rabe_cp_bsw_ciphertext_to_json(const void *ptr);

char *rabe_cp_bsw_master_key_to_json(const void *ptr);

void rabe_cp_bsw_free_secret_key(const void *ptr);

void rabe_cp_bsw_free_public_key(const void *ptr);

void rabe_cp_bsw_free_ciphertext(const void *ptr);

void rabe_cp_bsw_free_master_key(const void *ptr);

struct Mke08SetupResult rabe_cp_mke08_init(void);

const void *rabe_cp_mke08_generate_secret_authority_key(const char *name);

const void *rabe_cp_mke08_generate_user_key(const void *public_key,
                                            const void *master_key,
                                            const char *name);

int rabe_cp_mke08_add_attribute_to_user_key(const void *secret_authority_key,
                                            const void *user_key,
                                            const char *attr);

const void *rabe_cp_mke08_generate_public_attribute_key(
    const void *public_key, const char *attr, const void *secret_authority_key);

const void *rabe_cp_mke08_encrypt(const void *public_key,
                                  const void *const *public_attribute_keys,
                                  uintptr_t public_attribute_keys_len,
                                  const char *policy, const char *text,
                                  uintptr_t text_length);

struct CBoxedBuffer rabe_cp_mke08_decrypt(const void *public_key,
                                          const void *user_key,
                                          const void *cipher);

char *rabe_cp_mke08_master_key_to_json(const void *ptr);

char *rabe_cp_mke08_public_key_to_json(const void *ptr);

char *rabe_cp_mke08_public_attribute_key_to_json(const void *ptr);

char *rabe_cp_mke08_public_user_key_to_json(const void *ptr);

char *rabe_cp_mke08_secret_attribute_key_to_json(const void *ptr);

char *rabe_cp_mke08_secret_authority_key_to_json(const void *ptr);

char *rabe_cp_mke08_secret_user_key_to_json(const void *ptr);

char *rabe_cp_mke08_user_key_to_json(const void *ptr);

char *rabe_cp_mke08_ciphertext_to_json(const void *ptr);

const void *rabe_cp_mke08_master_key_from_json(const char *json);

const void *rabe_cp_mke08_public_key_from_json(const char *json);

const void *rabe_cp_mke08_public_attribute_key_from_json(const char *json);

const void *rabe_cp_mke08_public_user_key_from_json(const char *json);

const void *rabe_cp_mke08_secret_attribute_key_from_json(const char *json);

const void *rabe_cp_mke08_secret_authority_key_from_json(const char *json);

const void *rabe_cp_mke08_secret_user_key_from_json(const char *json);

const void *rabe_cp_mke08_user_key_from_json(const char *json);

const void *rabe_cp_mke08_ciphertext_from_json(const char *json);

void rabe_cp_mke08_free_master_key(const void *ptr);

void rabe_cp_mke08_free_public_key(const void *ptr);

void rabe_cp_mke08_free_public_attribute_key(const void *ptr);

void rabe_cp_mke08_free_public_user_key(const void *ptr);

void rabe_cp_mke08_free_secret_attribute_key(const void *ptr);

void rabe_cp_mke08_free_secret_authority_key(const void *ptr);

void rabe_cp_mke08_free_secret_user_key(const void *ptr);

void rabe_cp_mke08_free_user_key(const void *ptr);

void rabe_cp_mke08_free_ciphertext(const void *ptr);

const void *rabe_kp_ac17_generate_secret_key(const void *master_key,
                                             const char *policy);

const void *rabe_kp_ac17_encrypt(const void *public_key,
                                 const char *const *attr, uintptr_t attr_len,
                                 const char *text, uintptr_t text_length);

struct CBoxedBuffer rabe_kp_ac17_decrypt(const void *cipher,
                                         const void *secret_key);

char *rabe_kp_ac17_master_key_to_json(const void *ptr);

char *rabe_kp_ac17_public_key_to_json(const void *ptr);

char *rabe_kp_ac17_secret_key_to_json(const void *ptr);

char *rabe_kp_ac17_ciphertext_to_json(const void *ptr);

const void *rabe_kp_ac17_master_key_from_json(const char *json);

const void *rabe_kp_ac17_public_key_from_json(const char *json);

const void *rabe_kp_ac17_secret_key_from_json(const char *json);

const void *rabe_kp_ac17_ciphertext_from_json(const char *json);

void rabe_kp_ac17_free_master_key(const void *ptr);

void rabe_kp_ac17_free_public_key(const void *ptr);

void rabe_kp_ac17_free_secret_key(const void *ptr);

void rabe_kp_ac17_free_ciphertext(const void *ptr);

struct Yct14AbeSetupResult rabe_kp_yct14_init(const char *const *attrs,
                                              uintptr_t attr_len);

const void *rabe_kp_yct14_generate_secret_key(const void *public_key,
                                              const void *master_key,
                                              const char *policy);

const void *rabe_kp_yct14_encrypt(const void *public_key,
                                  const char *const *attrs, uintptr_t attr_len,
                                  const char *text, uintptr_t text_length);

struct CBoxedBuffer rabe_kp_yct14_decrypt(const void *cipher,
                                          const void *secret_key);

char *rabe_kp_yct14_ciphertext_to_json(const void *ptr);

char *rabe_kp_yct14_master_key_to_json(const void *ptr);

char *rabe_kp_yct14_public_key_to_json(const void *ptr);

char *rabe_kp_yct14_secret_key_to_json(const void *ptr);

const void *rabe_kp_yct14_ciphertext_from_json(const char *json);

const void *rabe_kp_yct14_master_key_from_json(const char *json);

const void *rabe_kp_yct14_public_key_from_json(const char *json);

const void *rabe_kp_yct14_secret_key_from_json(const char *json);

void rabe_kp_yct14_free_ciphertext(const void *ptr);

void rabe_kp_yct14_free_master_key(const void *ptr);

void rabe_kp_yct14_free_public_key(const void *ptr);

void rabe_kp_yct14_free_secret_key(const void *ptr);

struct LswSetupResult rabe_kp_lsw_init(void);

const void *rabe_kp_lsw_generate_secret_key(const void *public_key,
                                            const void *master_key,
                                            const char *policy);

const void *rabe_kp_lsw_encrypt(const void *public_key,
                                const char *const *attrs, uintptr_t attr_len,
                                const char *text, uintptr_t text_length);

struct CBoxedBuffer rabe_kp_lsw_decrypt(const void *cipher,
                                        const void *secret_key);

char *rabe_kp_lsw_master_key_to_json(const void *ptr);

char *rabe_kp_lsw_public_key_to_json(const void *ptr);

char *rabe_kp_lsw_secret_key_to_json(const void *ptr);

char *rabe_kp_lsw_ciphertext_to_json(const void *ptr);

const void *rabe_kp_lsw_master_key_from_json(const char *json);

const void *rabe_kp_lsw_public_key_from_json(const char *json);

const void *rabe_kp_lsw_secret_key_from_json(const char *json);

const void *rabe_kp_lsw_ciphertext_from_json(const char *json);

void rabe_kp_lsw_free_master_key(const void *ptr);

void rabe_kp_lsw_free_public_key(const void *ptr);

void rabe_kp_lsw_free_secret_key(const void *ptr);

void rabe_kp_lsw_free_ciphertext(const void *ptr);
