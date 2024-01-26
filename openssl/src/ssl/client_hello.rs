use std::ptr;
use std::slice;

use foreign_types::ForeignTypeRef;

use super::{NameType, SslRef, SslVersion, TlsExtType};

#[repr(transparent)]
pub struct ClientHello<'ssl>(pub(super) &'ssl ffi::SSL_CLIENT_HELLO);

impl ClientHello<'_> {
    /// Returns the data of a given extension, if present.
    ///
    /// This corresponds to [`SSL_early_callback_ctx_extension_get`].
    ///
    /// [`SSL_early_callback_ctx_extension_get`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_early_callback_ctx_extension_get
    pub fn get_extension(&self, ext_type: TlsExtType) -> Option<&[u8]> {
        unsafe {
            let mut ptr = ptr::null();
            let mut len = 0;
            let r = ffi::SSL_early_callback_ctx_extension_get(
                self.0,
                ext_type.as_raw() as _,
                &mut ptr,
                &mut len,
            );
            if r == 0 {
                None
            } else {
                Some(slice::from_raw_parts(ptr, len))
            }
        }
    }

    pub fn ssl_mut(&mut self) -> &mut SslRef {
        unsafe { SslRef::from_ptr_mut(self.0.ssl) }
    }

    pub fn ssl(&self) -> &SslRef {
        unsafe { SslRef::from_ptr(self.0.ssl) }
    }

    /// Returns the servername sent by the client via Server Name Indication (SNI).
    pub fn servername(&self, type_: NameType) -> Option<&str> {
        self.ssl().servername(type_)
    }

    /// Returns the version sent by the client in its Client Hello record.
    pub fn client_version(&self) -> SslVersion {
        SslVersion(self.0.version.into())
    }

    /// Returns a string describing the protocol version of the connection.
    pub fn version_str(&self) -> &'static str {
        self.ssl().version_str()
    }
}
