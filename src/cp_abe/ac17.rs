#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

use crate::common::THREAD_LAST_ERROR;
use crate::common::*;
use crate::{free_impl, from_json_impl, set_last_error, to_json_impl};
use rabe::schemes::ac17::{
    cp_decrypt, cp_encrypt, cp_keygen, setup, Ac17CpCiphertext, Ac17CpSecretKey, Ac17MasterKey,
    Ac17PublicKey,
};
use rabe::utils::policy::pest::PolicyLanguage;
use std::ffi::c_void;
#[allow(unused_imports)]
use std::ffi::{c_char, CString};
use std::ptr::null;
#[repr(C)]
pub struct Ac17SetupResult {
    pub master_key: *const c_void,
    pub public_key: *const c_void,
}

#[no_mangle]
pub unsafe extern "C" fn rabe_ac17_init() -> Ac17SetupResult {
    let (public_key, secret_key) = setup();
    Ac17SetupResult {
        master_key: Box::into_raw(Box::new(secret_key)) as *const c_void,
        public_key: Box::into_raw(Box::new(public_key)) as *const c_void,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_ac17_generate_secret_key(
    master_key: *const c_void,
    attr: *const *const c_char,
    attr_len: usize,
) -> *const c_void {
    let master_key = (master_key as *const Ac17MasterKey).as_ref();
    if let Some(master_key) = master_key {
        let attrs = cstring_array_to_string_vec(attr, attr_len);
        let key = cp_keygen(master_key, &attrs);
        if let Some(key) = key {
            Box::into_raw(Box::new(key)) as *const c_void
        } else {
            set_last_error!("Failed to generate secret key");
            null()
        }
    } else {
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_ac17_encrypt(
    public_key: *const c_void,
    policy: *const c_char,
    text: *const c_char,
    text_length: usize,
) -> *const c_void {
    let public_key = (public_key as *const Ac17PublicKey).as_ref();
    if let Some(public_key) = public_key {
        let policy_len = libc::strlen(policy);
        let policy = String::from_raw_parts(policy as *mut u8, policy_len, policy_len);
        let cipher = cp_encrypt(
            public_key,
            &policy,
            std::slice::from_raw_parts(text as *const u8, text_length),
            PolicyLanguage::HumanPolicy,
        );
        std::mem::forget(policy);
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
pub unsafe extern "C" fn rabe_cp_ac17_decrypt(
    cipher: *const c_void,
    secret_key: *const c_void,
) -> CBoxedBuffer {
    let cipher = (cipher as *const Ac17CpCiphertext).as_ref();
    let attr_key = (secret_key as *const Ac17CpSecretKey).as_ref();
    if let (Some(cipher), Some(attr_key)) = (cipher, attr_key) {
        let text = cp_decrypt(attr_key, cipher);
        match text {
            Ok(text) => vec_u8_to_cboxedbuffer(text),
            Err(err) => {
                set_last_error!(err);
                CBoxedBuffer::null()
            }
        }
    } else {
        set_last_error!("Invalid cipher or secret key");
        CBoxedBuffer::null()
    }
}

to_json_impl! {
    rabe_ac17_master_key_to_json,Ac17MasterKey,
    rabe_ac17_public_key_to_json,Ac17PublicKey,
    rabe_cp_ac17_secret_key_to_json,Ac17CpSecretKey,
    rabe_cp_ac17_cipher_to_json,Ac17CpCiphertext
}
from_json_impl! {
    rabe_ac17_master_key_from_json,Ac17MasterKey,
    rabe_ac17_public_key_from_json,Ac17PublicKey,
    rabe_cp_ac17_secret_key_from_json,Ac17CpSecretKey,
    rabe_cp_ac17_cipher_from_json,Ac17CpCiphertext
}

free_impl! {
    rabe_ac17_free_master_key,Ac17MasterKey,
    rabe_ac17_free_public_key,Ac17PublicKey,
    rabe_cp_ac17_free_secret_key,Ac17CpSecretKey,
    rabe_cp_ac17_free_cipher,Ac17CpCiphertext
}

#[cfg(test)]
mod test {
    use std::ffi::CString;

    use crate::common::{rabe_free_boxed_buffer, rabe_free_json};
    use crate::cp_abe::ac17::{
        rabe_ac17_free_master_key, rabe_ac17_free_public_key, rabe_ac17_init,
        rabe_ac17_public_key_to_json, rabe_cp_ac17_free_cipher, rabe_cp_ac17_generate_secret_key,
        rabe_cp_ac17_secret_key_to_json,
    };

    use super::{rabe_cp_ac17_cipher_to_json, rabe_cp_ac17_decrypt, rabe_cp_ac17_encrypt};

    #[test]
    fn test() {
        unsafe {
            let key = rabe_ac17_init();
            let public_key = key.public_key;
            let master_key = key.master_key;
            assert!(!public_key.is_null());
            assert!(!master_key.is_null());
            let attr = vec![CString::new("a").unwrap(), CString::new("b").unwrap()];
            let attr_ptr = attr.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
            let secret_key =
                rabe_cp_ac17_generate_secret_key(master_key, attr_ptr.as_ptr(), attr.len());
            assert!(!secret_key.is_null());
            let policy = CString::new("\"a\" and \"b\"").unwrap();
            let text = CString::new("hello world").unwrap();
            let cipher = rabe_cp_ac17_encrypt(
                public_key,
                policy.as_ptr(),
                text.as_ptr(),
                "hello world".len(),
            );
            assert!(!cipher.is_null());
            let result = rabe_cp_ac17_decrypt(cipher, secret_key);
            assert!(!result.buffer.is_null());
            assert_eq!(
                std::slice::from_raw_parts(result.buffer, result.len as usize),
                "hello world".as_bytes()
            );

            let json = rabe_cp_ac17_secret_key_to_json(secret_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_ac17_public_key_to_json(public_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_cp_ac17_cipher_to_json(cipher);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            rabe_cp_ac17_free_cipher(cipher);
            rabe_free_boxed_buffer(result);
            rabe_ac17_free_public_key(key.public_key);
            rabe_ac17_free_master_key(key.master_key);
        }
    }
}
