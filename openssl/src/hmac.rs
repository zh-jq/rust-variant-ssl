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
    /// Clears an existing HMAC_CTX and associated resources.
    ///
    /// This will make it suitable for new computations as if it was newly created with HMAC_CTX_new().
    #[corresponds(HMAC_CTX_reset)]
    #[cfg(any(ossl110, libressl350))]
    pub fn reset(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::HMAC_CTX_reset(self.as_ptr()))?;
            Ok(())
        }
    }

    /// Clears an existing HMAC_CTX and associated resources.
    ///
    /// This will make it suitable for new computations as if it was newly created with HMAC_CTX_new().
    #[corresponds(HMAC_CTX_reset)]
    #[cfg(boringssl)]
    pub fn reset(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            ffi::HMAC_CTX_reset(self.as_ptr());
            Ok(())
        }
    }

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

    /// Add data bytes to the MAC input.
    #[corresponds(HMAC_Update)]
    #[inline]
    pub fn hmac_update(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::HMAC_Update(
                self.as_ptr(),
                data.as_ptr() as *const _,
                data.len(),
            ))?;
        }

        Ok(())
    }

    /// Place the message authentication code in out.
    ///
    /// If `out` is set to `None`, an upper bound on the number of bytes required for the output buffer will be
    /// returned.
    #[corresponds(HMAC_Update)]
    #[inline]
    pub fn hmac_final(&mut self, out: Option<&mut [u8]>) -> Result<usize, ErrorStack> {
        let mut len = out
            .as_ref()
            .map_or(0, |b| u32::try_from(b.len()).unwrap_or(u32::MAX));

        unsafe {
            cvt(ffi::HMAC_Final(
                self.as_ptr(),
                out.map_or(ptr::null_mut(), |b| b.as_mut_ptr()),
                &mut len,
            ))?;
        }

        Ok(len as usize)
    }

    /// Like [`Self::hmac_final`] but appends the signature to a [`Vec`].
    pub fn hmac_final_to_vec(&mut self, out: &mut Vec<u8>) -> Result<usize, ErrorStack> {
        let base = out.len();
        let len = self.hmac_final(None)?;
        out.resize(base + len, 0);
        let len = self.hmac_final(Some(&mut out[base..]))?;
        out.truncate(base + len);
        Ok(len)
    }
}
