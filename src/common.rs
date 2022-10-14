use std::ffi::{c_char, c_uchar, c_void, CStr, CString};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[repr(C)]
pub struct CBoxedBuffer {
    pub(crate) buffer: *const c_uchar,
    pub(crate) len: usize,
}

impl Default for CBoxedBuffer {
    fn default() -> Self {
        CBoxedBuffer::null()
    }
}

impl CBoxedBuffer {
    pub fn null() -> Self {
        Self {
            buffer: std::ptr::null(),
            len: 0,
        }
    }
}

pub(crate) unsafe fn object_ptr_to_json<T: Serialize>(ptr: *const c_void) -> *mut c_char {
    let value = (ptr as *const T).as_ref();
    if let Some(value) = value {
        let json = serde_json::to_string(value);
        if let Ok(json) = json {
            CString::from_vec_unchecked(json.into_bytes()).into_raw()
        } else {
            std::ptr::null_mut()
        }
    } else {
        std::ptr::null_mut()
    }
}

pub(crate) unsafe fn json_to_object_ptr<T: DeserializeOwned>(json: *const c_char) -> *const c_void {
    let object = serde_json::from_slice::<T>(CStr::from_ptr(json).to_bytes());
    match object {
        Ok(object) => Box::into_raw(Box::new(object)) as *const c_void,
        Err(_) => std::ptr::null(),
    }
}

pub(crate) unsafe fn cstring_array_to_string_vec(array: *const *const c_char, len: usize) -> Vec<String> {
    (0..len).map(|index| {
        let c_str_ptr = array.add(index).read();
        CStr::from_ptr(c_str_ptr).to_string_lossy().to_string()
    }).collect::<Vec<_>>()
}


pub(crate) unsafe fn vec_u8_to_cboxedbuffer(mut array: Vec<u8>) -> CBoxedBuffer {
    array.shrink_to_fit();
    let len = array.len();
    let text_ptr = array.as_ptr();
    std::mem::forget(array);
    CBoxedBuffer { buffer: text_ptr, len }
}


#[no_mangle]
pub unsafe extern "C" fn rabe_free_json(json: *mut c_char) {
    let _ = Box::from_raw(json);
}

#[no_mangle]
pub unsafe extern "C" fn rabe_free_boxed_buffer(result: CBoxedBuffer) {
    let _ = Vec::from_raw_parts(result.buffer as *mut u8, result.len, result.len);
}

#[macro_export]
macro_rules! to_json_impl {
    ($($name:ident,$t:ty),*) => {
        $(
            #[no_mangle]
            pub unsafe extern "C" fn $name(ptr: *const c_void) -> *mut c_char {
                object_ptr_to_json::<$t>(ptr)
            }
        )*
    };
}
#[macro_export]
macro_rules! from_json_impl {
    ($($name:ident,$t:ty),*) => {
        $(
            #[no_mangle]
            pub unsafe extern "C" fn $name(json: *const c_char) -> *const c_void {
                json_to_object_ptr::<$t>(json)
            }
        )*
    };
}
#[macro_export]
macro_rules! free_impl {
    ($($name:ident,$t:ty),*) => {
        $(
            #[no_mangle]
            pub unsafe extern "C" fn $name(ptr: *const c_void){
                let _ = Box::from_raw(ptr as *mut $t);
            }
        )*
    };
}