use super::super::*;
use libc::*;

#[cfg(ossl300)]
extern "C" {
    pub fn OSSL_PARAM_construct_uint(key: *const c_char, buf: *mut c_uint) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_utf8_string(
        key: *const c_char,
        buf: *mut c_char,
        bsize: usize,
    ) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        bsize: usize,
    ) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_end() -> OSSL_PARAM;
}
