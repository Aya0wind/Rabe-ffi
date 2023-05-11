#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

use crate::common::THREAD_LAST_ERROR;
use libc::c_int;
use rabe::schemes::mke08::{
    authgen, decrypt, encrypt, keygen, request_authority_pk, request_authority_sk, setup,
    Mke08Ciphertext, Mke08MasterKey, Mke08PublicAttributeKey, Mke08PublicKey, Mke08PublicUserKey,
    Mke08SecretAttributeKey, Mke08SecretAuthorityKey, Mke08SecretUserKey, Mke08UserKey,
};
use rabe::utils::policy::pest::PolicyLanguage;
#[allow(unused_imports)]
use std::ffi::{c_char, CString};
use std::ffi::{c_void, CStr};
use std::ptr::null;

use crate::common::{json_to_object_ptr, object_ptr_to_json, vec_u8_to_cboxedbuffer, CBoxedBuffer};
use crate::{free_impl, from_json_impl, set_last_error, to_json_impl};

#[repr(C)]
pub struct Mke08SetupResult {
    pub master_key: *const c_void,
    pub public_key: *const c_void,
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_mke08_init() -> Mke08SetupResult {
    let (public_key, master_key) = setup();
    Mke08SetupResult {
        master_key: Box::into_raw(Box::new(master_key)) as *const c_void,
        public_key: Box::into_raw(Box::new(public_key)) as *const c_void,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_mke08_generate_secret_authority_key(
    name: *const c_char,
) -> *const c_void {
    let name = CStr::from_ptr(name).to_string_lossy().to_string();
    let key = authgen(&name);
    Box::into_raw(Box::new(key)) as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_mke08_generate_user_key(
    public_key: *const c_void,
    master_key: *const c_void,
    name: *const c_char,
) -> *const c_void {
    let public_key = (public_key as *const Mke08PublicKey).as_ref();
    let master_key = (master_key as *const Mke08MasterKey).as_ref();
    if let (Some(public_key), Some(master_key)) = (public_key, master_key) {
        let name = CStr::from_ptr(name).to_string_lossy().to_string();
        let key = keygen(public_key, master_key, &name);
        Box::into_raw(Box::new(key)) as *const c_void
    } else {
        set_last_error!("Invalid public or master key");
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_mke08_add_attribute_to_user_key(
    secret_authority_key: *const c_void,
    user_key: *const c_void,
    attr: *const c_char,
) -> c_int {
    let secret_authority_key = (secret_authority_key as *const Mke08SecretAuthorityKey).as_ref();
    if let Some(secret_authority_key) = secret_authority_key {
        let attr = CStr::from_ptr(attr).to_string_lossy().to_string();
        if let Some(user_key) = (user_key as *mut Mke08UserKey).as_mut() {
            user_key
                ._sk_a
                .push(request_authority_sk(&attr, secret_authority_key, &user_key._pk_u).unwrap());
            return 0;
        }
    }
    set_last_error!("Invalid secret authority key");
    -1
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_mke08_generate_public_attribute_key(
    public_key: *const c_void,
    attr: *const c_char,
    secret_authority_key: *const c_void,
) -> *const c_void {
    let public_key = (public_key as *const Mke08PublicKey).as_ref();
    let secret_authority_key = (secret_authority_key as *const Mke08SecretAuthorityKey).as_ref();
    if let (Some(public_key), Some(secret_authority_key)) = (public_key, secret_authority_key) {
        let attr = CStr::from_ptr(attr).to_string_lossy().to_string();
        match request_authority_pk(public_key, &attr, secret_authority_key) {
            Ok(public_attr_user_key) => {
                return Box::into_raw(Box::new(public_attr_user_key)) as *const c_void;
            }
            Err(err) => {
                set_last_error!(err);
                return null();
            }
        }
    }
    set_last_error!("Invalid public key or secret authority key");
    null()
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_mke08_encrypt(
    public_key: *const c_void,
    public_attribute_keys: *const *const c_void,
    public_attribute_keys_len: usize,
    policy: *const c_char,
    text: *const c_char,
    text_length: usize,
) -> *const c_void {
    let public_key = (public_key as *const Mke08PublicKey).as_ref();
    if let Some(public_key) = public_key {
        let policy_len = libc::strlen(policy);
        let policy = String::from_raw_parts(policy as *mut u8, policy_len, policy_len);
        let attr_slice =
            std::slice::from_raw_parts(public_attribute_keys, public_attribute_keys_len);
        let public_attribute_keys = attr_slice
            .iter()
            .map(|x| (*x as *mut Mke08PublicAttributeKey).read())
            .collect::<Vec<_>>();
        let cipher = encrypt(
            public_key,
            &public_attribute_keys,
            &policy,
            PolicyLanguage::HumanPolicy,
            std::slice::from_raw_parts(text as *const u8, text_length),
        );
        std::mem::forget(policy);
        let _ = Vec::from_raw_parts(
            public_attribute_keys.as_ptr() as *mut *const c_void,
            public_attribute_keys.len(),
            public_attribute_keys.capacity(),
        );
        std::mem::forget(public_attribute_keys);
        match cipher {
            Ok(cipher) => Box::into_raw(Box::new(cipher)) as *const c_void,
            Err(err) => {
                set_last_error!(err);
                null()
            }
        }
    } else {
        set_last_error!("Invalid public key");
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_mke08_decrypt(
    public_key: *const c_void,
    user_key: *const c_void,
    cipher: *const c_void,
) -> CBoxedBuffer {
    let cipher = (cipher as *const Mke08Ciphertext).as_ref();
    let public_key = (public_key as *const Mke08PublicKey).as_ref();
    let user_key = (user_key as *const Mke08UserKey).as_ref();
    if let (Some(cipher), Some(public_key), Some(user_key)) = (cipher, public_key, user_key) {
        let text = decrypt(public_key, user_key, cipher);
        match text {
            Ok(text) => vec_u8_to_cboxedbuffer(text),
            Err(err) => {
                set_last_error!(err);
                CBoxedBuffer::default()
            }
        }
    } else {
        set_last_error!("Invalid public key or user key");
        CBoxedBuffer::null()
    }
}
// Mke08Ciphertext,
// Mke08MasterKey,
// Mke08PublicAttributeKey,
// Mke08PublicKey,
// Mke08PublicUserKey,
// Mke08SecretAttributeKey,
// Mke08SecretAuthorityKey,
// Mke08SecretUserKey,
// Mke08UserKey,
to_json_impl! {
    rabe_cp_mke08_master_key_to_json,Mke08MasterKey,
    rabe_cp_mke08_public_key_to_json,Mke08PublicKey,
    rabe_cp_mke08_public_attribute_key_to_json,Mke08PublicAttributeKey,
    rabe_cp_mke08_public_user_key_to_json,Mke08PublicUserKey,
    rabe_cp_mke08_secret_attribute_key_to_json,Mke08SecretAttributeKey,
    rabe_cp_mke08_secret_authority_key_to_json,Mke08SecretAuthorityKey,
    rabe_cp_mke08_secret_user_key_to_json,Mke08SecretUserKey,
    rabe_cp_mke08_user_key_to_json,Mke08UserKey,
    rabe_cp_mke08_ciphertext_to_json,Mke08Ciphertext
}
from_json_impl! {
    rabe_cp_mke08_master_key_from_json,Mke08MasterKey,
    rabe_cp_mke08_public_key_from_json,Mke08PublicKey,
    rabe_cp_mke08_public_attribute_key_from_json,Mke08PublicAttributeKey,
    rabe_cp_mke08_public_user_key_from_json,Mke08PublicUserKey,
    rabe_cp_mke08_secret_attribute_key_from_json,Mke08SecretAttributeKey,
    rabe_cp_mke08_secret_authority_key_from_json,Mke08SecretAuthorityKey,
    rabe_cp_mke08_secret_user_key_from_json,Mke08SecretUserKey,
    rabe_cp_mke08_user_key_from_json,Mke08UserKey,
    rabe_cp_mke08_ciphertext_from_json,Mke08Ciphertext
}
free_impl! {
    rabe_cp_mke08_free_master_key,Mke08MasterKey,
    rabe_cp_mke08_free_public_key,Mke08PublicKey,
    rabe_cp_mke08_free_public_attribute_key,Mke08PublicAttributeKey,
    rabe_cp_mke08_free_public_user_key,Mke08PublicUserKey,
    rabe_cp_mke08_free_secret_attribute_key,Mke08SecretAttributeKey,
    rabe_cp_mke08_free_secret_authority_key,Mke08SecretAuthorityKey,
    rabe_cp_mke08_free_secret_user_key,Mke08SecretUserKey,
    rabe_cp_mke08_free_user_key,Mke08UserKey,
    rabe_cp_mke08_free_ciphertext,Mke08Ciphertext
}

#[cfg(test)]
mod test {
    use std::ffi::CString;

    use crate::common::{rabe_free_boxed_buffer, rabe_free_json};
    use crate::cp_abe::mke08::{
        rabe_cp_mke08_add_attribute_to_user_key, rabe_cp_mke08_ciphertext_from_json,
        rabe_cp_mke08_ciphertext_to_json, rabe_cp_mke08_decrypt, rabe_cp_mke08_encrypt,
        rabe_cp_mke08_free_ciphertext, rabe_cp_mke08_free_master_key,
        rabe_cp_mke08_free_public_attribute_key, rabe_cp_mke08_free_public_key,
        rabe_cp_mke08_free_secret_authority_key, rabe_cp_mke08_free_user_key,
        rabe_cp_mke08_generate_public_attribute_key, rabe_cp_mke08_generate_secret_authority_key,
        rabe_cp_mke08_generate_user_key, rabe_cp_mke08_init, rabe_cp_mke08_master_key_from_json,
        rabe_cp_mke08_master_key_to_json, rabe_cp_mke08_public_attribute_key_from_json,
        rabe_cp_mke08_public_attribute_key_to_json, rabe_cp_mke08_public_key_from_json,
        rabe_cp_mke08_public_key_to_json, rabe_cp_mke08_secret_authority_key_from_json,
        rabe_cp_mke08_secret_authority_key_to_json, rabe_cp_mke08_user_key_from_json,
        rabe_cp_mke08_user_key_to_json,
    };

    #[test]
    fn test() {
        unsafe {
            // use rabe::schemes::mke08::*;
            // use rabe::utils::policy::pest::PolicyLanguage;
            // let (_pk, _msk) = setup();
            // let mut _u_key = keygen(&_pk, &_msk, &String::from("user1"));
            // let _att1 = String::from("aa1::A");
            // let _att2 = String::from("aa2::B");
            // let _a1_key = authgen(&String::from("aa1"));
            // let _a2_key = authgen(&String::from("aa2"));
            // let _att1_pk = request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
            // let _att2_pk = request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
            // _u_key._sk_a.push(request_authority_sk(&_att1, &_a1_key, &_u_key._pk_u).unwrap());
            // _u_key._sk_a.push(request_authority_sk(&_att2, &_a2_key, &_u_key._pk_u).unwrap());
            // let _plaintext = String::from("our plaintext!").into_bytes();
            // let _policy = String::from(r#""aa1::A" and "aa2::B""#);
            // let _ct: Mke08Ciphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, PolicyLanguage::HumanPolicy, &_plaintext).unwrap();
            // assert_eq!(decrypt(&_pk, &_u_key, &_ct).unwrap(), _plaintext);

            //generate public and master key
            let key = rabe_cp_mke08_init();
            let public_key = key.public_key;
            let master_key = key.master_key;
            assert!(!public_key.is_null());
            assert!(!master_key.is_null());

            //serialize and deserialize public and master key test
            let public_key_json = rabe_cp_mke08_public_key_to_json(public_key);
            assert!(!public_key_json.is_null());
            rabe_cp_mke08_free_public_key(public_key);
            let public_key = rabe_cp_mke08_public_key_from_json(public_key_json);
            assert!(!public_key.is_null());
            rabe_free_json(public_key_json);

            let master_key_json = rabe_cp_mke08_master_key_to_json(master_key);
            assert!(!master_key_json.is_null());
            rabe_cp_mke08_free_master_key(master_key);
            let master_key = rabe_cp_mke08_master_key_from_json(master_key_json);
            assert!(!master_key.is_null());

            //generate user key
            let name = CString::new("user1").unwrap();
            let user_key = rabe_cp_mke08_generate_user_key(public_key, master_key, name.as_ptr());
            //serialize and deserialize user key test
            let user_key_json = rabe_cp_mke08_user_key_to_json(user_key);
            assert!(!user_key_json.is_null());
            rabe_cp_mke08_free_user_key(user_key);
            let user_key = rabe_cp_mke08_user_key_from_json(user_key_json);
            assert!(!user_key.is_null());
            rabe_free_json(user_key_json);

            let attr = CString::new("aa1").unwrap();
            //generate secret authority key
            let secret_authority_key = rabe_cp_mke08_generate_secret_authority_key(attr.as_ptr());
            assert!(!secret_authority_key.is_null());
            //serialize and deserialize secret authority key test
            let secret_authority_key_json =
                rabe_cp_mke08_secret_authority_key_to_json(secret_authority_key);
            assert!(!secret_authority_key.is_null());
            rabe_cp_mke08_free_secret_authority_key(secret_authority_key);
            let secret_authority_key =
                rabe_cp_mke08_secret_authority_key_from_json(secret_authority_key_json);
            assert!(!secret_authority_key.is_null());
            rabe_free_json(secret_authority_key_json);

            //generate secret authority key1
            let attr1 = CString::new("aa2").unwrap();
            let secret_authority_key1 = rabe_cp_mke08_generate_secret_authority_key(attr1.as_ptr());

            //generate public attribute key
            let attr = CString::new("aa1::A").unwrap();
            let public_attribute_key = rabe_cp_mke08_generate_public_attribute_key(
                public_key,
                attr.as_ptr(),
                secret_authority_key,
            );
            assert!(!public_attribute_key.is_null());
            //serialize and deserialize public attribute key test
            let public_attribute_key_json =
                rabe_cp_mke08_public_attribute_key_to_json(public_attribute_key);
            assert!(!public_attribute_key_json.is_null());
            rabe_cp_mke08_free_public_attribute_key(public_attribute_key);
            let public_attribute_key =
                rabe_cp_mke08_public_attribute_key_from_json(public_attribute_key_json);
            assert!(!public_attribute_key.is_null());
            rabe_free_json(public_attribute_key_json);

            //generate public attribute key1
            let attr1 = CString::new("aa2::B").unwrap();
            let public_attribute_key1 = rabe_cp_mke08_generate_public_attribute_key(
                public_key,
                attr1.as_ptr(),
                secret_authority_key1,
            );

            //add attribute key to user key
            rabe_cp_mke08_add_attribute_to_user_key(secret_authority_key, user_key, attr.as_ptr());

            //add attribute key1 to user key
            rabe_cp_mke08_add_attribute_to_user_key(
                secret_authority_key1,
                user_key,
                attr1.as_ptr(),
            );

            let policy = CString::new(r#""aa1::A" and "aa2::B""#).unwrap();
            let text = CString::new("hello world").unwrap();
            let public_keys = vec![public_attribute_key, public_attribute_key1];
            let cipher = rabe_cp_mke08_encrypt(
                public_key,
                public_keys.as_ptr(),
                public_keys.len(),
                policy.as_ptr(),
                text.as_ptr(),
                "hello world".len(),
            );
            assert!(!cipher.is_null());
            //serialize and deserialize ciphertext test
            let cipher_json = rabe_cp_mke08_ciphertext_to_json(cipher);
            assert!(!cipher_json.is_null());
            rabe_cp_mke08_free_ciphertext(cipher);
            let cipher = rabe_cp_mke08_ciphertext_from_json(cipher_json);
            assert!(!cipher.is_null());
            rabe_free_json(cipher_json);

            let result = rabe_cp_mke08_decrypt(public_key, user_key, cipher);
            assert!(!result.buffer.is_null());
            assert_eq!(
                std::slice::from_raw_parts(result.buffer, result.len as usize),
                "hello world".as_bytes()
            );
            rabe_free_boxed_buffer(result);

            rabe_cp_mke08_free_ciphertext(cipher);
            rabe_cp_mke08_free_public_key(key.public_key);
            rabe_cp_mke08_free_master_key(key.master_key);
            rabe_cp_mke08_free_user_key(user_key);
            rabe_cp_mke08_free_secret_authority_key(secret_authority_key);
            rabe_cp_mke08_free_secret_authority_key(secret_authority_key1);
            rabe_cp_mke08_free_public_attribute_key(public_attribute_key);
            rabe_cp_mke08_free_public_attribute_key(public_attribute_key1);
        }
    }
}
