#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

use crate::common::THREAD_LAST_ERROR;
use crate::common::{
    cstring_array_to_string_vec, json_to_object_ptr, object_ptr_to_json, vec_u8_to_cboxedbuffer,
    CBoxedBuffer,
};
use crate::{free_impl, from_json_impl, set_last_error, to_json_impl};
use rabe::schemes::aw11::{
    authgen, decrypt, encrypt, keygen, setup, Aw11Ciphertext, Aw11GlobalKey, Aw11MasterKey,
    Aw11PublicKey, Aw11SecretKey,
};
use rabe::utils::policy::pest::PolicyLanguage;
use std::ffi::c_char;
use std::ffi::CString;
use std::ffi::{c_void, CStr};
use std::ptr::null;

#[repr(C)]
pub struct Aw11AuthGenResult {
    pub master_key: *const c_void,
    pub public_key: *const c_void,
}

impl Default for Aw11AuthGenResult {
    fn default() -> Self {
        Self {
            master_key: null(),
            public_key: null(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_aw11_init() -> *const c_void {
    let global_key = setup();
    Box::into_raw(Box::new(global_key)) as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_aw11_generate_auth(
    global_key: *const c_void,
    attrs: *const *const c_char,
    attr_len: usize,
) -> Aw11AuthGenResult {
    let global_key = (global_key as *const Aw11GlobalKey).as_ref();
    if let Some(global_key) = global_key {
        let attrs = cstring_array_to_string_vec(attrs, attr_len);
        let key = authgen(global_key, &attrs);
        if let Some(key) = key {
            Aw11AuthGenResult {
                master_key: Box::into_raw(Box::new(key.1)) as *const c_void,
                public_key: Box::into_raw(Box::new(key.0)) as *const c_void,
            }
        } else {
            set_last_error!("Failed to generate auth key");
            Default::default()
        }
    } else {
        set_last_error!("Invalid global key");
        Default::default()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_aw11_generate_secret_key(
    global_key: *const c_void,
    master_key: *const c_void,
    name: *const c_char,
    attrs: *const *const c_char,
    attr_len: usize,
) -> *const c_void {
    let global_key = (global_key as *const Aw11GlobalKey).as_ref();
    let master_key = (master_key as *const Aw11MasterKey).as_ref();
    if let (Some(global_key), Some(master_key)) = (global_key, master_key) {
        let attrs = cstring_array_to_string_vec(attrs, attr_len);
        let name = CStr::from_ptr(name).to_string_lossy().to_string();
        let key = keygen(global_key, master_key, &name, &attrs);
        std::mem::forget(name);
        match key {
            Ok(key) => Box::into_raw(Box::new(key)) as *const c_void,
            Err(err) => {
                set_last_error!(err);
                null()
            }
        }
    } else {
        set_last_error!("Invalid global key or master key");
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_aw11_encrypt(
    global_key: *const c_void,
    public_keys: *const *const c_void,
    public_keys_len: usize,
    policy: *const c_char,
    text: *const c_char,
    text_length: usize,
) -> *const c_void {
    let global_key = (global_key as *const Aw11GlobalKey).as_ref();
    if let Some(global_key) = global_key {
        let policy_len = libc::strlen(policy);
        let policy = String::from_raw_parts(policy as *mut u8, policy_len, policy_len);
        let public_keys = std::slice::from_raw_parts(public_keys, public_keys_len)
            .iter()
            .map(|x| (*x as *const Aw11PublicKey).read())
            .collect::<Vec<_>>();
        let cipher = encrypt(
            global_key,
            &public_keys,
            &policy,
            PolicyLanguage::HumanPolicy,
            std::slice::from_raw_parts(text as *const u8, text_length),
        );
        std::mem::forget(public_keys);
        std::mem::forget(policy);
        match cipher {
            Ok(cipher) => Box::into_raw(Box::new(cipher)) as *const c_void,
            Err(err) => {
                set_last_error!(err);
                null()
            }
        }
    } else {
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_aw11_decrypt(
    global_key: *const c_void,
    secret_key: *const c_void,
    cipher: *const c_void,
) -> CBoxedBuffer {
    let cipher = (cipher as *const Aw11Ciphertext).as_ref();
    let attr_key = (secret_key as *const Aw11SecretKey).as_ref();
    let global_key = (global_key as *const Aw11GlobalKey).as_ref();
    if let (Some(global_key), Some(secret_key), Some(cipher)) = (global_key, attr_key, cipher) {
        let text = decrypt(global_key, secret_key, cipher);
        match text {
            Ok(text) => vec_u8_to_cboxedbuffer(text),
            Err(err) => {
                set_last_error!(err);
                Default::default()
            }
        }
    } else {
        set_last_error!("Invalid global key or secret key or cipher");
        CBoxedBuffer::null()
    }
}

from_json_impl! {
    rabe_cp_aw11_master_key_from_json,Aw11MasterKey,
    rabe_cp_aw11_public_key_from_json,Aw11PublicKey,
    rabe_cp_aw11_secret_key_from_json,Aw11SecretKey,
    rabe_cp_aw11_ciphertext_from_json,Aw11Ciphertext,
    rabe_cp_aw11_global_key_from_json,Aw11GlobalKey
}
to_json_impl! {
    rabe_cp_aw11_master_key_to_json,Aw11MasterKey,
    rabe_cp_aw11_public_key_to_json,Aw11PublicKey,
    rabe_cp_aw11_secret_key_to_json,Aw11SecretKey,
    rabe_cp_aw11_ciphertext_to_json,Aw11Ciphertext,
    rabe_cp_aw11_global_key_to_json,Aw11GlobalKey
}
free_impl! {
    rabe_cp_aw11_free_master_key,Aw11MasterKey,
    rabe_cp_aw11_free_public_key,Aw11PublicKey,
    rabe_cp_aw11_free_secret_key,Aw11SecretKey,
    rabe_cp_aw11_free_ciphertext,Aw11Ciphertext,
    rabe_cp_aw11_free_global_key,Aw11GlobalKey
}

#[cfg(test)]
mod test {
    use crate::common::{rabe_free_boxed_buffer, rabe_free_json};
    use crate::cp_abe::aw11::{
        rabe_aw11_init, rabe_cp_aw11_ciphertext_to_json, rabe_cp_aw11_decrypt,
        rabe_cp_aw11_encrypt, rabe_cp_aw11_free_ciphertext, rabe_cp_aw11_free_master_key,
        rabe_cp_aw11_free_public_key, rabe_cp_aw11_generate_auth, rabe_cp_aw11_generate_secret_key,
        rabe_cp_aw11_public_key_to_json, rabe_cp_aw11_secret_key_to_json,
    };
    use std::ffi::CString;

    #[test]
    fn test() {
        unsafe {
            let global_key = rabe_aw11_init();
            let attrs = vec![CString::new("A").unwrap(), CString::new("B").unwrap()];
            let attr_ptr = attrs.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
            let key = rabe_cp_aw11_generate_auth(global_key, attr_ptr.as_ptr(), attr_ptr.len());
            let public_key = key.public_key;
            let master_key = key.master_key;

            assert!(!public_key.is_null());
            assert!(!master_key.is_null());
            let name = CString::new("A").unwrap();
            let secret_key = rabe_cp_aw11_generate_secret_key(
                global_key,
                master_key,
                name.as_ptr(),
                attr_ptr.as_ptr(),
                attr_ptr.len(),
            );
            assert!(!secret_key.is_null());
            let policy = CString::new("\"A\" and \"B\"").unwrap();
            let text = CString::new("hello world").unwrap();
            let public_keys = vec![public_key];
            let cipher = rabe_cp_aw11_encrypt(
                global_key,
                public_keys.as_ptr(),
                public_keys.len(),
                policy.as_ptr(),
                text.as_ptr(),
                "hello world".len(),
            );
            assert!(!cipher.is_null());
            let result = rabe_cp_aw11_decrypt(global_key, secret_key, cipher);
            assert!(!result.buffer.is_null());
            assert_eq!(
                std::slice::from_raw_parts(result.buffer, result.len as usize),
                "hello world".as_bytes()
            );

            let json = rabe_cp_aw11_secret_key_to_json(secret_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_cp_aw11_public_key_to_json(public_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            let json = rabe_cp_aw11_ciphertext_to_json(cipher);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_free_json(json);
            rabe_cp_aw11_free_ciphertext(cipher);
            rabe_free_boxed_buffer(result);
            rabe_cp_aw11_free_public_key(key.public_key);
            rabe_cp_aw11_free_master_key(key.master_key);
        }
    }
}
