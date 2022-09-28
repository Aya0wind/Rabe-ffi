#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#[allow(unused_imports)]
use std::ffi::{c_char, CString};
use std::ffi::{c_void, CStr};
use std::ptr::null;

use libc::c_uchar;
use rabe::{
    schemes::ac17,
    utils::policy::pest::PolicyLanguage,
};
use rabe::schemes::ac17::{Ac17CpCiphertext, Ac17CpSecretKey, Ac17MasterKey, Ac17PublicKey, cp_decrypt, cp_keygen};

#[repr(C)]
pub struct InitKeyResult {
    pub_key: *const c_void,
    master_key: *const c_void,
}

#[no_mangle]
pub unsafe extern "C" fn rabe_init() -> InitKeyResult {
    let (pub_key, master_key) = ac17::setup();
    InitKeyResult {
        pub_key: Box::into_raw(Box::new(pub_key)) as *const c_void,
        master_key: Box::into_raw(Box::new(master_key)) as *const c_void,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_deserialize_pub_key(json: *const c_char) -> *const c_void{
    let pub_key = serde_json::from_slice::<Ac17PublicKey>(CStr::from_ptr(json).to_bytes()).unwrap();
    Box::into_raw(Box::new(pub_key)) as *const c_void
}
#[no_mangle]
pub unsafe extern "C" fn rabe_deserialize_master_key(json: *const c_char) -> *const c_void{
    let master_key = serde_json::from_slice::<Ac17MasterKey>(CStr::from_ptr(json).to_bytes()).unwrap();
    Box::into_raw(Box::new(master_key)) as *const c_void
}
#[no_mangle]
pub unsafe extern "C" fn rabe_deserialize_secret_key(json: *const c_char) -> *const c_void{
    let cp_secret_key = serde_json::from_slice::<Ac17CpSecretKey>(CStr::from_ptr(json).to_bytes()).unwrap();
    Box::into_raw(Box::new(cp_secret_key)) as *const c_void
}
#[no_mangle]
pub unsafe extern "C" fn rabe_deserialize_ciphertext(json: *const c_char) -> *const c_void{
    let cp_ciphertext = serde_json::from_slice::<Ac17CpCiphertext>(CStr::from_ptr(json).to_bytes()).unwrap();
    Box::into_raw(Box::new(cp_ciphertext)) as *const c_void
}


#[no_mangle]
pub unsafe extern "C" fn rabe_generate_sec_key(master_key: *const c_void, attr: *const *const c_char, attr_len: usize) -> *const c_void {
    let master_key = (master_key as *const Ac17MasterKey).as_ref().unwrap();
    let vec = (0..attr_len).map(|index| {
        let c_str_ptr = attr.add(index).read();
        let string = std::slice::from_raw_parts(c_str_ptr as *const u8, libc::strlen(c_str_ptr));
        String::from_utf8_lossy(string).to_string()
    }).collect::<Vec<_>>();
    let key = cp_keygen(master_key, &vec);
    if let Some(key) = key {
        Box::into_raw(Box::new(key)) as *const c_void
    } else {
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_encrypt(pub_key: *const c_void, policy: *const c_char, text: *const c_char, text_length: usize) -> *const c_void {
    let pub_key = (pub_key as *const Ac17PublicKey).as_ref().unwrap();
    let policy_len = libc::strlen(policy);
    let policy = String::from_raw_parts(policy as *mut u8, policy_len, policy_len);
    let cipher = ac17::cp_encrypt(
        pub_key,
        &policy,
        std::slice::from_raw_parts(text as *const u8, text_length),
        PolicyLanguage::HumanPolicy,
    );
    std::mem::forget(policy);
    if let Ok(cipher) = cipher {
        Box::into_raw(Box::new(cipher)) as *const c_void
    } else {
        null()
    }
}

#[repr(C)]
pub struct DecryptResult {
    buffer: *const c_uchar,
    len: usize,
}


#[no_mangle]
pub unsafe extern "C" fn rabe_decrypt(cipher: *const c_void, sec_key: *const c_void) -> DecryptResult {
    let cipher = (cipher as *const Ac17CpCiphertext).as_ref().unwrap();
    let attr_key = (sec_key as *const Ac17CpSecretKey).as_ref().unwrap();
    let text = cp_decrypt(attr_key, cipher);
    if let Ok(mut text) = text {
        text.shrink_to_fit();
        let len = text.len();
        let text_ptr = text.as_ptr();
        std::mem::forget(text);
        DecryptResult { buffer:text_ptr , len }
    } else {
        DecryptResult { buffer: null(), len: 0 }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_free_decrypt_result(result: DecryptResult) {
    let _ = Vec::from_raw_parts(result.buffer as *mut u8, result.len, result.len);
}

#[no_mangle]
pub unsafe extern "C" fn rabe_free_init_result(result: InitKeyResult) {
    let _ = Box::from_raw(result.pub_key as *mut Ac17PublicKey);
    let _ = Box::from_raw(result.master_key as *mut Ac17MasterKey);
}

#[no_mangle]
pub unsafe extern "C" fn rabe_free_pub_key(pub_key: *const c_void) {
    let _ = Box::<Ac17PublicKey>::from_raw(pub_key as *mut Ac17PublicKey);
}

#[no_mangle]
pub unsafe extern "C" fn rabe_free_master_key(master_key: *const c_void) {
    let _ = Box::<Ac17MasterKey>::from_raw(master_key as *mut Ac17MasterKey);
}


#[no_mangle]
pub unsafe extern "C" fn rabe_free_sec_key(sec_key: *const c_void) {
    let _ = Box::<Ac17CpSecretKey>::from_raw(sec_key as *mut Ac17CpSecretKey);
}

#[no_mangle]
pub unsafe extern "C" fn rabe_free_cipher(cipher: *const c_void) {
    let _ = Box::<Ac17CpCiphertext>::from_raw(cipher as *mut Ac17CpCiphertext);
}


#[no_mangle]
pub unsafe extern "C" fn rabe_master_key_to_json(sec_key: *const c_void) -> *mut c_char {
    let sec_key = (sec_key as *const Ac17MasterKey).as_ref().unwrap();
    let json = serde_json::to_string(sec_key).unwrap();
    CString::from_vec_unchecked(json.into_bytes()).into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rabe_pub_key_to_json(pub_key: *const c_void) -> *mut c_char {
    let pub_key = (pub_key as *const Ac17PublicKey).as_ref().unwrap();
    let json = serde_json::to_string(pub_key).unwrap();
    CString::from_vec_unchecked(json.into_bytes()).into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rabe_sec_key_to_json(sec_key: *const c_void) -> *mut c_char {
    let pub_key = (sec_key as *const Ac17CpSecretKey).as_ref().unwrap();
    let json = serde_json::to_string(pub_key).unwrap();
    CString::from_vec_unchecked(json.into_bytes()).into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cipher_to_json(cipher: *const c_void) -> *mut c_char {
    let cipher = (cipher as *const Ac17CpCiphertext).as_ref().unwrap();
    let json = serde_json::to_string(cipher).unwrap();
    CString::from_vec_unchecked(json.into_bytes()).into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rabe_free_json(json: *mut c_char){
    let _ = Box::<u8>::from_raw(json as *mut u8);
}


#[cfg(test)]
mod test {
    use std::ffi::CString;

    use crate::{rabe_cipher_to_json, rabe_decrypt, rabe_encrypt, rabe_free_cipher, rabe_free_decrypt_result, rabe_free_init_result, rabe_free_json, rabe_generate_sec_key, rabe_init, rabe_pub_key_to_json, rabe_master_key_to_json};

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
            let attr_key = rabe_generate_sec_key(sec_key, attr_ptr.as_ptr(), attr.len());
            assert!(!attr_key.is_null());
            let policy = CString::new("\"a\" and \"b\"").unwrap();
            let text = CString::new("hello world").unwrap();
            let cipher = rabe_encrypt(pub_key,
                                      policy.as_ptr(),
                                      text.as_ptr(),
                                      "hello world".len());
            assert!(!cipher.is_null());
            let result = rabe_decrypt(cipher, attr_key);
            assert!(!result.buffer.is_null());
            assert_eq!(std::slice::from_raw_parts(result.buffer, result.len), "hello world".as_bytes());

            let json = rabe_master_key_to_json(sec_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_pub_key_to_json(pub_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_cipher_to_json(cipher);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            rabe_free_cipher(cipher);
            rabe_free_decrypt_result(result);
            rabe_free_init_result(key);
        }
    }
}