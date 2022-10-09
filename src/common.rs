use std::ffi::{c_char, c_uchar, c_void, CStr, CString};
use rabe::schemes::ac17;
use rabe::schemes::ac17::{Ac17MasterKey, Ac17PublicKey};

#[repr(C)]
pub struct InitKeyResult {
    pub pub_key: *const c_void,
    pub master_key: *const c_void,
}
#[repr(C)]
pub struct DecryptResult {
    pub(crate) buffer: *const c_uchar,
    pub(crate) len: usize,
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
pub unsafe extern "C" fn rabe_free_json(json: *mut c_char){
    let _ = Box::<u8>::from_raw(json as *mut u8);
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


