use crate::{ptr::PtrOptWrite, result::PbmxResult};
use libc::size_t;
use pbmx_kit::serde::Message;
use std::slice;

pub unsafe fn ffi_export<T>(t: &T, buf: *mut u8, len: *mut size_t) -> PbmxResult
where
    T: Message,
{
    if buf.is_null() && len.is_null() {
        None?
    }
    let bytes = t.encode().ok()?;
    if *len < bytes.len() {
        len.opt_write(bytes.len());
        None?
    } else {
        let buf = slice::from_raw_parts_mut(buf, *len);
        buf[..bytes.len()].copy_from_slice(&bytes);
        PbmxResult::ok()
    }
}
pub unsafe fn ffi_import<T>(buf: *const u8, len: size_t) -> Option<T>
where
    T: Message,
{
    let buf = slice::from_raw_parts(buf, len);
    T::decode(buf).ok()
}
