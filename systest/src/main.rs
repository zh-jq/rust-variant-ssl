#![allow(bad_style, deprecated, clippy::all)]

use libc::*;
use variant_ssl_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
