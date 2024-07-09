use crate::error::ErrorStack;
use crate::md::MdRef;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::HMAC_CTX;
    fn drop = ffi::HMAC_CTX_free;

    /// A context object used to perform MAC operations.
    pub struct HMacCtx;
    /// A reference to a [`HmacCtx`].
    pub struct HMacCtxRef;
}

impl HMacCtx {
    /// Creates a new context.
    #[corresponds(HMAC_CTX_new)]
    pub fn new() -> Result<Self, ErrorStack> {
        ffi::init();

        unsafe {
            let ptr = cvt_p(ffi::HMAC_CTX_new())?;
            Ok(HMacCtx::from_ptr(ptr))
        }
    }
}

impl HMacCtxRef {
    #[corresponds(HMAC_CTX_copy)]
    pub fn copy(&mut self, src: &HMacCtxRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::HMAC_CTX_copy(self.as_ptr(), src.as_ptr()))?;
            Ok(())
        }
    }

    #[corresponds(HMAC_Init_ex)]
    pub fn init_ex(&mut self, key: Option<&[u8]>, md: &MdRef) -> Result<(), ErrorStack> {
        let key_len = key.map(|v| v.len()).unwrap_or_default();
        #[cfg(not(boringssl))]
        let key_len = i32::try_from(key_len).unwrap();
        let key = key.map(|v| v.as_ptr()).unwrap_or(ptr::null());
        unsafe {
            cvt(ffi::HMAC_Init_ex(
                self.as_ptr(),
                key as _,
                key_len,
                md.as_ptr(),
                ptr::null_mut(),
            ))?;
            Ok(())
        }
    }
}
