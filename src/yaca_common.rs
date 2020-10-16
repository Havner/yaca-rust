use libc::c_void;
use std::clone;
use std::slice;

use crate::yaca_lib as lib;


pub(crate) fn vector_from_raw<U, T>(length: usize, data: *const U) -> Vec<T>
    where T: clone::Clone,
{
    assert!(!data.is_null());
    assert!(length > 0);
    unsafe {
        let v = slice::from_raw_parts(data as *const T, length).to_vec();
        lib::yaca_free(data as *mut c_void);
        v
    }
}
