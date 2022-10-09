#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

#[allow(unused_imports)]
use std::ffi::{c_char, CString};
use std::ffi::{c_void, CStr};
use std::ptr::null;

use rabe::{
    schemes::ac17,
    utils::policy::pest::PolicyLanguage,
};
use rabe::schemes::ac17::{Ac17KpCiphertext, Ac17KpSecretKey, Ac17MasterKey, Ac17PublicKey, kp_decrypt, kp_encrypt, kp_keygen};

use crate::common::{DecryptResult, InitKeyResult};

#[no_mangle]
pub unsafe extern "C" fn rabe_deserialize_kp_sec_key(json: *const c_char) -> *const c_void {
    let kp_secret_key = serde_json::from_slice::<Ac17KpSecretKey>(CStr::from_ptr(json).to_bytes()).unwrap();
    Box::into_raw(Box::new(kp_secret_key)) as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn rabe_deserialize_kp_cipher(json: *const c_char) -> *const c_void {
    let kp_ciphertext = serde_json::from_slice::<Ac17KpCiphertext>(CStr::from_ptr(json).to_bytes()).unwrap();
    Box::into_raw(Box::new(kp_ciphertext)) as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn rabe_generate_kp_sec_key(master_key: *const c_void, policy: *const c_char) -> *const c_void {
    let master_key = (master_key as *const Ac17MasterKey).as_ref().unwrap();
    let policy_len = libc::strlen(policy);
    let policy = String::from_raw_parts(policy as *mut u8, policy_len, policy_len);
    let cipher = kp_keygen(
        master_key,
        &policy,
        PolicyLanguage::HumanPolicy,
    );
    std::mem::forget(policy);
    if let Ok(cipher) = cipher {
        Box::into_raw(Box::new(cipher)) as *const c_void
    } else {
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_kp_encrypt(pub_key: *const c_void, attr: *const *const c_char, attr_len: usize, text: *const c_char, text_length: usize) -> *const c_void {
    let pub_key = (pub_key as *const Ac17PublicKey).as_ref().unwrap();
    let attrs = (0..attr_len).map(|index| {
        let c_str_ptr = attr.add(index).read();
        let string = std::slice::from_raw_parts(c_str_ptr as *const u8, libc::strlen(c_str_ptr));
        String::from_utf8_lossy(string).to_string()
    }).collect::<Vec<_>>();
    let cipher = kp_encrypt(
        pub_key,
        &attrs,
        std::slice::from_raw_parts(text as *const u8, text_length),
    );
    if let Ok(cipher) = cipher {
        Box::into_raw(Box::new(cipher)) as *const c_void
    } else {
        null()
    }
}


#[no_mangle]
pub unsafe extern "C" fn rabe_kp_decrypt(cipher: *const c_void, sec_key: *const c_void) -> DecryptResult {
    let cipher = (cipher as *const Ac17KpCiphertext).as_ref().unwrap();
    let attr_key = (sec_key as *const Ac17KpSecretKey).as_ref().unwrap();
    let text = kp_decrypt(attr_key, cipher);
    if let Ok(mut text) = text {
        text.shrink_to_fit();
        let len = text.len();
        let text_ptr = text.as_ptr();
        std::mem::forget(text);
        DecryptResult { buffer: text_ptr, len }
    } else {
        DecryptResult { buffer: null(), len: 0 }
    }
}


#[no_mangle]
pub unsafe extern "C" fn rabe_free_kp_sec_key(sec_key: *const c_void) {
    let _ = Box::<Ac17KpSecretKey>::from_raw(sec_key as *mut Ac17KpSecretKey);
}

#[no_mangle]
pub unsafe extern "C" fn rabe_free_kp_cipher(cipher: *const c_void) {
    let _ = Box::<Ac17KpCiphertext>::from_raw(cipher as *mut Ac17KpCiphertext);
}

#[no_mangle]
pub unsafe extern "C" fn rabe_kp_sec_key_to_json(sec_key: *const c_void) -> *mut c_char {
    let pub_key = (sec_key as *const Ac17KpSecretKey).as_ref().unwrap();
    let json = serde_json::to_string(pub_key).unwrap();
    CString::from_vec_unchecked(json.into_bytes()).into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rabe_kp_cipher_to_json(cipher: *const c_void) -> *mut c_char {
    let cipher = (cipher as *const Ac17KpCiphertext).as_ref().unwrap();
    let json = serde_json::to_string(cipher).unwrap();
    CString::from_vec_unchecked(json.into_bytes()).into_raw()
}


#[cfg(test)]
mod test {
    use std::ffi::CString;

    use crate::common::{rabe_free_decrypt_result, rabe_free_init_result, rabe_free_json, rabe_init, rabe_master_key_to_json, rabe_pub_key_to_json};

    use super::{rabe_free_kp_cipher, rabe_generate_kp_sec_key, rabe_kp_cipher_to_json, rabe_kp_decrypt, rabe_kp_encrypt};

    #[test]
    fn test() {
        unsafe {
            let key = rabe_init();
            let pub_key = key.pub_key;
            let sec_key = key.master_key;
            assert!(!pub_key.is_null());
            assert!(!sec_key.is_null());
            let attr = vec![CString::new("a").unwrap(), CString::new("b").unwrap()];
            let attr_ptr = attr.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
            let policy = CString::new("\"a\" and \"b\"").unwrap();
            let attr_key = rabe_generate_kp_sec_key(sec_key, policy.as_ptr());
            assert!(!attr_key.is_null());
            let text = CString::new("hello world").unwrap();
            let cipher = rabe_kp_encrypt(pub_key,
                                         attr_ptr.as_ptr(),
                                         attr.len(),
                                         text.as_ptr(),
                                         "hello world".len());
            assert!(!cipher.is_null());
            let result = rabe_kp_decrypt(cipher, attr_key);
            assert!(!result.buffer.is_null());
            assert_eq!(std::slice::from_raw_parts(result.buffer, result.len), "hello world".as_bytes());

            let json = rabe_master_key_to_json(sec_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_pub_key_to_json(pub_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_kp_cipher_to_json(cipher);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            rabe_free_kp_cipher(cipher);
            rabe_free_decrypt_result(result);
            rabe_free_init_result(key);
        }
    }
}