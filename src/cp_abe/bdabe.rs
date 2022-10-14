#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

#[allow(unused_imports)]
use std::ffi::{c_char, CString};
use std::ffi::{c_void, CStr};
use std::ptr::null;

use libc::c_int;
use rabe::schemes::bdabe::{authgen,
                           BdabeCiphertext,
                           BdabeMasterKey,
                           BdabePublicAttributeKey,
                           BdabePublicKey,
                           BdabePublicUserKey,
                           BdabeSecretAttributeKey,
                           BdabeSecretAuthorityKey,
                           BdabeSecretUserKey,
                           BdabeUserKey,
                           decrypt,
                           encrypt,
                           keygen,
                           request_attribute_pk,
                           request_attribute_sk,
                           setup,
};
use rabe::utils::policy::pest::PolicyLanguage;

use crate::common::{CBoxedBuffer, json_to_object_ptr, object_ptr_to_json, vec_u8_to_cboxedbuffer};
use crate::{free_impl, from_json_impl, to_json_impl};

#[repr(C)]
pub struct BdabeSetupResult {
    pub master_key: *const c_void,
    pub public_key: *const c_void,
}


#[no_mangle]
pub unsafe extern "C" fn rabe_cp_bdabe_init() -> BdabeSetupResult {
    let (public_key, master_key) = setup();
    BdabeSetupResult {
        master_key: Box::into_raw(Box::new(master_key)) as *const c_void,
        public_key: Box::into_raw(Box::new(public_key)) as *const c_void,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_bdabe_generate_sec_auth_key(
    public_key: *const c_void,
    master_key: *const c_void,
    name: *const c_char) -> *const c_void {
    let public_key = (public_key as *const BdabePublicKey).as_ref();
    let master_key = (master_key as *const BdabeMasterKey).as_ref();
    if let Some(public_key) = public_key {
        if let Some(master_key) = master_key {
            let name = CStr::from_ptr(name).to_string_lossy().to_string();
            let key = authgen(public_key, master_key, &name);
            Box::into_raw(Box::new(key)) as *const c_void
        } else {
            null()
        }
    } else {
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_bdabe_generate_sec_attr_key(
    pub_user_key: *const c_void,
    sec_auth_key: *const c_void,
    attr: *const c_char) -> *const c_void {
    let pub_user_key = (pub_user_key as *const BdabePublicUserKey).as_ref();
    let sec_auth_key = (sec_auth_key as *const BdabeSecretAuthorityKey).as_ref();
    if let (Some(pub_user_key), Some(sec_auth_key)) = (pub_user_key, sec_auth_key) {
        let attr = CStr::from_ptr(attr).to_string_lossy().to_string();
        let key = request_attribute_sk(pub_user_key, sec_auth_key, &attr);
        if let Ok(key) = key {
            Box::into_raw(Box::new(key)) as *const c_void
        } else {
            null()
        }
    } else {
        null()
    }
}


#[no_mangle]
pub unsafe extern "C" fn rabe_cp_bdabe_generate_user_key(
    public_key: *const c_void,
    sec_auth_key: *const c_void,
    name: *const c_char,
) -> *const c_void {
    let public_key = (public_key as *const BdabePublicKey).as_ref();
    let sec_auth_key = (sec_auth_key as *const BdabeSecretAuthorityKey).as_ref();
    if let (Some(public_key), Some(sec_auth_key)) = (public_key, sec_auth_key) {
        let name = CStr::from_ptr(name).to_string_lossy().to_string();
        let key = keygen(public_key, sec_auth_key, &name);
        Box::into_raw(Box::new(key)) as *const c_void
    } else {
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_bdabe_generate_pub_attr_key(
    public_key: *const c_void,
    sec_auth_key: *const c_void,
    name: *const c_char,
) -> *const c_void {
    let public_key = (public_key as *const BdabePublicKey).as_ref();
    let sec_auth_key = (sec_auth_key as *const BdabeSecretAuthorityKey).as_ref();
    if let (Some(public_key), Some(sec_auth_key)) = (public_key, sec_auth_key) {
        let name = CStr::from_ptr(name).to_string_lossy().to_string();
        let key = request_attribute_pk(public_key, sec_auth_key, &name);
        if let Ok(key) = key {
            Box::into_raw(Box::new(key)) as *const c_void
        } else {
            null()
        }
    } else {
        null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_bdabe_add_attr_to_user_key(
    sec_auth_key: *const c_void,
    user_key: *const c_void,
    attr: *const c_char,
) -> c_int {
    let sec_auth_key = (sec_auth_key as *const BdabeSecretAuthorityKey).as_ref();
    if let Some(sec_auth_key) = sec_auth_key {
        let attr = CStr::from_ptr(attr).to_string_lossy().to_string();
        if let Some(user_key) = (user_key as *mut BdabeUserKey).as_mut() {
            user_key._ska.push(request_attribute_sk(&user_key._pk, sec_auth_key, &attr).unwrap());
            return 0;
        }
    }
    -1
}

#[no_mangle]
pub unsafe extern "C" fn rabe_cp_bdabe_encrypt(
    public_key: *const c_void,
    pub_attr_keys: *const *const c_void,
    pub_attr_keys_len: usize,
    policy: *const c_char,
    text: *const c_char,
    text_length: usize) -> *const c_void {
    let public_key = (public_key as *const BdabePublicKey).as_ref();
    if let Some(public_key) = public_key {
        let policy_len = libc::strlen(policy);
        let policy = String::from_raw_parts(policy as *mut u8, policy_len, policy_len);
        let pub_attr_keys = std::slice::from_raw_parts(pub_attr_keys, pub_attr_keys_len)
            .iter()
            .map(|x| (*x as *mut BdabePublicAttributeKey).read())
            .collect::<Vec<_>>();
        let cipher = encrypt(
            public_key,
            &pub_attr_keys,
            &policy,
            std::slice::from_raw_parts(text as *const u8, text_length),
            PolicyLanguage::HumanPolicy,
        );
        std::mem::forget(policy);
        let _ = Vec::from_raw_parts(pub_attr_keys.as_ptr() as *mut *const c_void, pub_attr_keys.len(), pub_attr_keys.capacity());
        std::mem::forget(pub_attr_keys);
        if let Ok(cipher) = cipher {
            Box::into_raw(Box::new(cipher)) as *const c_void
        } else {
            null()
        }
    } else {
        null()
    }
}


#[no_mangle]
pub unsafe extern "C" fn rabe_cp_bdabe_decrypt(
    public_key: *const c_void,
    user_key: *const c_void,
    cipher: *const c_void) -> CBoxedBuffer {
    let cipher = (cipher as *const BdabeCiphertext).as_ref();
    let public_key = (public_key as *const BdabePublicKey).as_ref();
    let user_key = (user_key as *const BdabeUserKey).as_ref();
    if let (Some(cipher), Some(public_key), Some(user_key)) = (cipher, public_key, user_key) {
        let text = decrypt(public_key, user_key, cipher);
        if let Ok(text) = text {
            vec_u8_to_cboxedbuffer(text)
        } else {
            CBoxedBuffer::null()
        }
    } else {
        CBoxedBuffer::null()
    }
}

to_json_impl!{
    rabe_cp_bdabe_public_user_key_to_json,BdabePublicUserKey,
    rabe_cp_bdabe_secret_user_key_to_json,BdabeSecretUserKey,
    rabe_cp_bdabe_master_key_to_json,BdabeMasterKey,
    rabe_cp_bdabe_public_key_to_json,BdabePublicKey,
    rabe_cp_bdabe_secret_authority_key_to_json,BdabeSecretAuthorityKey,
    rabe_cp_bdabe_secret_attribute_key_to_json,BdabeSecretAttributeKey,
    rabe_cp_bdabe_public_attribute_key_to_json,BdabePublicAttributeKey,
    rabe_cp_bdabe_user_key_to_json,BdabeUserKey,
    rabe_cp_bdabe_ciphertext_to_json,BdabeCiphertext}

from_json_impl!{
    rabe_cp_bdabe_public_user_key_from_json,BdabePublicUserKey,
    rabe_cp_bdabe_secret_user_key_from_json,BdabeSecretUserKey,
    rabe_cp_bdabe_master_key_from_json,BdabeMasterKey,
    rabe_cp_bdabe_public_key_from_json,BdabePublicKey,
    rabe_cp_bdabe_secret_authority_key_from_json,BdabeSecretAuthorityKey,
    rabe_cp_bdabe_secret_attribute_key_from_json,BdabeSecretAttributeKey,
    rabe_cp_bdabe_public_attribute_key_from_json,BdabePublicAttributeKey,
    rabe_cp_bdabe_user_key_from_json,BdabeUserKey,
    rabe_cp_bdabe_ciphertext_from_json,BdabeCiphertext}

free_impl!{
    rabe_cp_bdabe_free_public_user_key,BdabePublicUserKey,
    rabe_cp_bdabe_free_secret_user_key,BdabeSecretUserKey,
    rabe_cp_bdabe_free_master_key,BdabeMasterKey,
    rabe_cp_bdabe_free_public_key,BdabePublicKey,
    rabe_cp_bdabe_free_secret_authority_key,BdabeSecretAuthorityKey,
    rabe_cp_bdabe_free_secret_attribute_key,BdabeSecretAttributeKey,
    rabe_cp_bdabe_free_public_attribute_key,BdabePublicAttributeKey,
    rabe_cp_bdabe_free_user_key,BdabeUserKey,
    rabe_cp_bdabe_free_ciphertext,BdabeCiphertext}


#[cfg(test)]
mod test {
    use std::ffi::CString;

    use libc::c_char;

    use crate::common::{rabe_free_boxed_buffer, rabe_free_json};
    use crate::cp_abe::bdabe::{rabe_cp_bdabe_add_attr_to_user_key, rabe_cp_bdabe_ciphertext_from_json, rabe_cp_bdabe_ciphertext_to_json, rabe_cp_bdabe_decrypt, rabe_cp_bdabe_encrypt, rabe_cp_bdabe_free_ciphertext, rabe_cp_bdabe_free_master_key, rabe_cp_bdabe_free_public_attribute_key, rabe_cp_bdabe_free_public_key, rabe_cp_bdabe_free_secret_authority_key, rabe_cp_bdabe_free_user_key, rabe_cp_bdabe_generate_pub_attr_key, rabe_cp_bdabe_generate_sec_auth_key, rabe_cp_bdabe_generate_user_key, rabe_cp_bdabe_init, rabe_cp_bdabe_master_key_from_json, rabe_cp_bdabe_master_key_to_json, rabe_cp_bdabe_public_attribute_key_from_json, rabe_cp_bdabe_public_attribute_key_to_json, rabe_cp_bdabe_public_key_from_json, rabe_cp_bdabe_public_key_to_json, rabe_cp_bdabe_secret_authority_key_from_json, rabe_cp_bdabe_secret_authority_key_to_json, rabe_cp_bdabe_user_key_from_json, rabe_cp_bdabe_user_key_to_json};

    #[test]
    fn test() {
        unsafe {
            // use rabe::schemes::bdabe::*;
            // use rabe::utils::policy::pest::PolicyLanguage;
            // let (_pk, _msk) = setup();
            //
            // let _a1_key = authgen(&_pk, &_msk, &String::from("aa1"));
            // let mut _u_key = keygen(&_pk, &_a1_key, &String::from("u1"));
            // let _att1 = String::from("aa1::A");
            // let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
            // _u_key._ska.push(request_attribute_sk(&_u_key._pk, &_a1_key, &_att1).unwrap());
            // let _plaintext = String::from("our plaintext!").into_bytes();
            // let _policy = String::from(r#""aa1::A" or "aa1::B""#);
            // let _ct: BdabeCiphertext = encrypt(&_pk, &vec![_att1_pk], &_policy, &_plaintext, PolicyLanguage::HumanPolicy).unwrap();
            // let _match = decrypt(&_pk, &_u_key, &_ct);
            // assert_eq!(_match.is_ok(), true);
            // assert_eq!(_match.unwrap(), _plaintext);

            //generate public key and master key
            let key = rabe_cp_bdabe_init();
            let public_key = key.public_key;
            let master_key = key.master_key;
            assert!(!public_key.is_null());
            assert!(!master_key.is_null());

            //serialize and deserialize public key and master key test
            let json = rabe_cp_bdabe_public_key_to_json(public_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_cp_bdabe_free_public_key(public_key);
            let public_key = rabe_cp_bdabe_public_key_from_json(json);
            rabe_free_json(json);

            let json = rabe_cp_bdabe_master_key_to_json(master_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_cp_bdabe_free_master_key(master_key);
            let master_key = rabe_cp_bdabe_master_key_from_json(json);
            rabe_free_json(json);


            //generate authority key
            let name = CString::new("aa1").unwrap();
            let sec_auth_key = rabe_cp_bdabe_generate_sec_auth_key(public_key, master_key, name.as_ptr());
            assert!(!sec_auth_key.is_null());

            // generate user key
            let user_key = rabe_cp_bdabe_generate_user_key(
                public_key,
                sec_auth_key,
                name.as_ptr(),
            );
            assert!(!user_key.is_null());

            //serialize and deserialize user key test
            let json = rabe_cp_bdabe_secret_authority_key_to_json(sec_auth_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_cp_bdabe_free_secret_authority_key(sec_auth_key);
            let sec_auth_key = rabe_cp_bdabe_secret_authority_key_from_json(json);
            rabe_free_json(json);

            let json = rabe_cp_bdabe_user_key_to_json(user_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_cp_bdabe_free_user_key(user_key);
            let user_key = rabe_cp_bdabe_user_key_from_json(json);
            rabe_free_json(json);


            //generate public attribute key
            let attr = CString::new("aa1::A").unwrap();
            let pub_attr_key = rabe_cp_bdabe_generate_pub_attr_key(public_key, sec_auth_key, attr.as_ptr());

            //add attribute key to user key
            rabe_cp_bdabe_add_attr_to_user_key(sec_auth_key, user_key, attr.as_ptr());

            //serialize and deserialize public attribute key test
            let json = rabe_cp_bdabe_public_attribute_key_to_json(pub_attr_key);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_cp_bdabe_free_public_attribute_key(pub_attr_key);
            let pub_attr_key = rabe_cp_bdabe_public_attribute_key_from_json(json);
            rabe_free_json(json);

            //encrypt test
            let _plaintext = String::from("our plaintext!").into_bytes();
            let _policy = CString::new(r#""aa1::A" or "aa1::B""#).unwrap();
            let pub_attr_keys = vec![pub_attr_key];
            let cipher = rabe_cp_bdabe_encrypt(public_key,
                                               pub_attr_keys.as_ptr(),
                                               pub_attr_keys.len(),
                                               _policy.as_ptr(),
                                               _plaintext.as_ptr() as *const c_char,
                                               _plaintext.len());
            assert!(!cipher.is_null());

            //serialize and deserialize cipher test
            let json = rabe_cp_bdabe_ciphertext_to_json(cipher);
            println!("{}", std::ffi::CStr::from_ptr(json).to_str().unwrap());
            rabe_cp_bdabe_free_ciphertext(cipher);
            let cipher = rabe_cp_bdabe_ciphertext_from_json(json);
            rabe_free_json(json);

            //decrypt test
            let result = rabe_cp_bdabe_decrypt(public_key, user_key, cipher);
            assert!(!result.buffer.is_null());
            assert_eq!(std::slice::from_raw_parts(result.buffer, result.len), "our plaintext!".as_bytes());
            rabe_free_boxed_buffer(result);

            //free memory
            rabe_cp_bdabe_free_public_key(public_key);
            rabe_cp_bdabe_free_master_key(master_key);
            rabe_cp_bdabe_free_secret_authority_key(sec_auth_key);
            rabe_cp_bdabe_free_user_key(user_key);
            rabe_cp_bdabe_free_public_attribute_key(pub_attr_key);
            rabe_cp_bdabe_free_ciphertext(cipher);
        }
    }
}
