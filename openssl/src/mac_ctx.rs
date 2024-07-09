use crate::cvt;
use crate::error::ErrorStack;
use foreign_types::ForeignType;
use std::ffi::CStr;
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_MAC_CTX;
    fn drop = ffi::EVP_MAC_CTX_free;
    fn clone = ffi::EVP_MAC_CTX_dup;

    /// A context object used to perform MAC operations.
    pub struct MacCtx;
    /// A reference to a [`HmacCtx`].
    pub struct MacCtxRef;
}

impl MacCtx {
    /// Set key and digest
    pub fn init_ex(&mut self, key: Option<&[u8]>, md: &CStr) -> Result<(), ErrorStack> {
        let key_field_name = CStr::from_bytes_with_nul(b"key\0").unwrap();
        let digest_field_name = CStr::from_bytes_with_nul(b"digest\0").unwrap();

        let key_len = key.map(|v| v.len()).unwrap_or_default();
        let key = key.map(|v| v.as_ptr()).unwrap_or(ptr::null());

        unsafe {
            let param_key =
                ffi::OSSL_PARAM_construct_octet_string(key_field_name.as_ptr(), key as _, key_len);
            let param_digest = ffi::OSSL_PARAM_construct_utf8_string(
                digest_field_name.as_ptr(),
                md.as_ptr() as _,
                md.to_bytes().len(),
            );
            let param_end = ffi::OSSL_PARAM_construct_end();

            let params = [param_key, param_digest, param_end];

            cvt(ffi::EVP_MAC_CTX_set_params(self.as_ptr(), params.as_ptr()))?;
        }
        Ok(())
    }
}
