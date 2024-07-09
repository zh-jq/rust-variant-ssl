use super::super::*;
use libc::*;

extern "C" {
    pub fn SSL_get_servername(ssl: *const SSL, name_type: c_int) -> *const c_char;

    pub fn SSL_export_keying_material(
        s: *mut SSL,
        out: *mut c_uchar,
        olen: size_t,
        label: *const c_char,
        llen: size_t,
        context: *const c_uchar,
        contextlen: size_t,
        use_context: c_int,
    ) -> c_int;

    #[cfg(ossl111)]
    pub fn SSL_export_keying_material_early(
        s: *mut SSL,
        out: *mut c_uchar,
        olen: size_t,
        label: *const c_char,
        llen: size_t,
        context: *const c_uchar,
        contextlen: size_t,
    ) -> c_int;

    #[cfg(ossl300)]
    pub fn SSL_CTX_set_tlsext_ticket_key_evp_cb(
        ctx: *mut SSL_CTX,
        fp: Option<
            unsafe extern "C" fn(
                arg1: *mut SSL,
                arg2: *mut c_uchar,
                arg3: *mut c_uchar,
                arg4: *mut EVP_CIPHER_CTX,
                arg5: *mut EVP_MAC_CTX,
                arg6: c_int,
            ) -> c_int,
        >,
    ) -> c_int;
}
