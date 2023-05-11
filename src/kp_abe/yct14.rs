#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

use crate::common::THREAD_LAST_ERROR;
use rabe::schemes::yct14::{
    decrypt, encrypt, keygen, setup, Yct14AbeCiphertext, Yct14AbeMasterKey, Yct14AbePublicKey,
    Yct14AbeSecretKey,
};
use rabe::utils::policy::pest::PolicyLanguage;
use std::ffi::c_void;
#[allow(unused_imports)]
use std::ffi::{c_char, CString};
use std::ptr::null;

use crate::common::{
    cstring_array_to_string_vec, json_to_object_ptr, object_ptr_to_json, vec_u8_to_cboxedbuffer,
    CBoxedBuffer,
};
use crate::{free_impl, from_json_impl, set_last_error, to_json_impl};

#[repr(C)]
pub struct Yct14AbeSetupResult {
    pub master_key: *const c_void,
    pub public_key: *const c_void,
}

#[no_mangle]
pub unsafe extern "C" fn rabe_kp_yct14_init(
    attrs: *const *const c_char,
    attr_len: usize,
) -> Yct14AbeSetupResult {
    let attrs = cstring_array_to_string_vec(attrs, attr_len);
    let (public_key, master_key) = setup(attrs);
    Yct14AbeSetupResult {
        master_key: Box::into_raw(Box::new(master_key)) as *const c_void,
        public_key: Box::into_raw(Box::new(public_key)) as *const c_void,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_kp_yct14_generate_secret_key(
    public_key: *const c_void,
    master_key: *const c_void,
    policy: *const c_char,
) -> *const c_void {
    let master_key = (master_key as *const Yct14AbeMasterKey).as_ref();
    let public_key = (public_key as *const Yct14AbePublicKey).as_ref();
    if let (Some(master_key), Some(public_key)) = (master_key, public_key) {
        let policy_len = libc::strlen(policy);
        let policy = String::from_raw_parts(policy as *mut u8, policy_len, policy_len);
        let key = keygen(public_key, master_key, &policy, PolicyLanguage::HumanPolicy);
        std::mem::forget(policy);
        match key {
            Ok(key) => Box::into_raw(Box::new(key)) as *const c_void,
            Err(err) => {
                set_last_error!(err);
                null()
            }
        }
    } else {
        set_last_error!("Invalid master key or public key");
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_kp_yct14_encrypt(
    public_key: *const c_void,
    attrs: *const *const c_char,
    attr_len: usize,
    text: *const c_char,
    text_length: usize,
) -> *const c_void {
    let public_key = (public_key as *const Yct14AbePublicKey).as_ref();
    if let Some(public_key) = public_key {
        let attrs = cstring_array_to_string_vec(attrs, attr_len);
        let cipher = encrypt(
            public_key,
            &attrs,
            std::slice::from_raw_parts(text as *const u8, text_length),
        );
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
pub unsafe extern "C" fn rabe_kp_yct14_decrypt(
    cipher: *const c_void,
    secret_key: *const c_void,
) -> CBoxedBuffer {
    let cipher = (cipher as *const Yct14AbeCiphertext).as_ref();
    let attr_key = (secret_key as *const Yct14AbeSecretKey).as_ref();
    if let (Some(cipher), Some(attr_key)) = (cipher, attr_key) {
        let text = decrypt(attr_key, cipher);
        match text {
            Ok(text) => vec_u8_to_cboxedbuffer(text),
            Err(err) => {
                set_last_error!(err);
                CBoxedBuffer::default()
            }
        }
    } else {
        set_last_error!("Invalid cipher or secret key");
        CBoxedBuffer::null()
    }
}
// Yct14AbeCiphertext,
// Yct14AbeMasterKey,
// Yct14AbePublicKey,
// Yct14AbeSecretKey,
to_json_impl! {
    rabe_kp_yct14_ciphertext_to_json,Yct14AbeCiphertext,
    rabe_kp_yct14_master_key_to_json,Yct14AbeMasterKey,
    rabe_kp_yct14_public_key_to_json,Yct14AbePublicKey,
    rabe_kp_yct14_secret_key_to_json,Yct14AbeSecretKey
}
from_json_impl! {
    rabe_kp_yct14_ciphertext_from_json,Yct14AbeCiphertext,
    rabe_kp_yct14_master_key_from_json,Yct14AbeMasterKey,
    rabe_kp_yct14_public_key_from_json,Yct14AbePublicKey,
    rabe_kp_yct14_secret_key_from_json,Yct14AbeSecretKey
}
free_impl! {
    rabe_kp_yct14_free_ciphertext,Yct14AbeCiphertext,
    rabe_kp_yct14_free_master_key,Yct14AbeMasterKey,
    rabe_kp_yct14_free_public_key,Yct14AbePublicKey,
    rabe_kp_yct14_free_secret_key,Yct14AbeSecretKey
}

#[cfg(test)]
mod test {
    use std::ffi::CString;

    use crate::common::{rabe_free_boxed_buffer, rabe_free_json};
    use crate::kp_abe::yct14::{
        rabe_kp_yct14_ciphertext_to_json, rabe_kp_yct14_decrypt, rabe_kp_yct14_encrypt,
        rabe_kp_yct14_free_ciphertext, rabe_kp_yct14_free_master_key,
        rabe_kp_yct14_free_public_key, rabe_kp_yct14_generate_secret_key, rabe_kp_yct14_init,
        rabe_kp_yct14_public_key_to_json, rabe_kp_yct14_secret_key_to_json,
    };

    #[test]
    fn test() {
        unsafe {
            let attr = vec![CString::new("a").unwrap(), CString::new("b").unwrap()];
            let attr_ptr = attr.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
            let key = rabe_kp_yct14_init(attr_ptr.as_ptr(), attr.len());
            let public_key = key.public_key;
            let master_key = key.master_key;
            assert!(!public_key.is_null());
            assert!(!master_key.is_null());
            let policy = CString::new("\"a\" and \"b\"").unwrap();
            let secret_key =
                rabe_kp_yct14_generate_secret_key(public_key, master_key, policy.as_ptr());
            assert!(!secret_key.is_null());

            let text = CString::new("hello world").unwrap();
            let cipher = rabe_kp_yct14_encrypt(
                public_key,
                attr_ptr.as_ptr(),
                attr.len(),
                text.as_ptr(),
                "hello world".len(),
            );
            assert!(!cipher.is_null());
            let result = rabe_kp_yct14_decrypt(cipher, secret_key);
            assert!(!result.buffer.is_null());
            assert_eq!(
                std::slice::from_raw_parts(result.buffer, result.len as usize),
                "hello world".as_bytes()
            );

            let json = rabe_kp_yct14_secret_key_to_json(secret_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_kp_yct14_public_key_to_json(public_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_kp_yct14_ciphertext_to_json(cipher);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            rabe_kp_yct14_free_ciphertext(cipher);
            rabe_free_boxed_buffer(result);
            rabe_kp_yct14_free_public_key(key.public_key);
            rabe_kp_yct14_free_master_key(key.master_key);
        }
    }
}
