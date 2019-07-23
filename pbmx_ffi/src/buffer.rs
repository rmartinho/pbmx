use crate::result::PbmxResult;
use libc::{c_char, size_t};
use std::slice;

pub struct BufferFillPtr<T>(*mut T);

impl<T> BufferFillPtr<T> {
    pub fn new(ptr: *mut T) -> Option<BufferFillPtr<T>> {
        if ptr.is_null() {
            None
        } else {
            Some(BufferFillPtr(ptr))
        }
    }

    pub unsafe fn push(&mut self, t: T) {
        self.0.write(t);
        self.0 = self.0.offset(1);
    }
}

pub unsafe fn return_list<T, It>(iter: It, ptr: *mut T, len: *mut size_t) -> PbmxResult
where
    It: ExactSizeIterator<Item = T>,
{
    let len = &mut *len;
    let n = iter.len();
    if *len < n {
        *len = n;
        return None?;
    }

    if ptr.is_null() {
        return None?;
    }

    let slice = slice::from_raw_parts_mut(ptr, *len);
    for (t, s) in iter.zip(slice.iter_mut()) {
        *s = t;
    }

    PbmxResult::ok()
}

pub unsafe fn return_string(s: &str, ptr: *mut c_char, len: *mut size_t) -> PbmxResult {
    if *len < s.len() {
        *len = s.len();
        return None?;
    }
    let slice = slice::from_raw_parts_mut(ptr as *mut u8, *len);
    slice[..s.len()].copy_from_slice(s.as_bytes());
    PbmxResult::ok()
}

pub unsafe fn return_kv_list<T, It>(
    iter: It,
    k_idx_out: *mut size_t,
    len: *mut size_t,
    k_out: *mut c_char,
    k_len: *mut size_t,
    v_out: *mut T,
) -> PbmxResult
where
    It: ExactSizeIterator<Item = (String, T)>,
{
    let n = iter.len();
    let (k, v): (Vec<_>, Vec<_>) = iter.unzip();
    let l = k.iter().map(|s| s.len()).sum();
    let len = &mut *len;
    let k_len = &mut *k_len;
    if *len < n || *k_len < l {
        *len = n;
        *k_len = l;
        return None?;
    }

    if v_out.is_null() {
        return None?;
    }

    let mut k_slice = slice::from_raw_parts_mut(k_out as *mut u8, *k_len);
    let idx_slice = slice::from_raw_parts_mut(k_idx_out, *len);
    let v_slice = slice::from_raw_parts_mut(v_out, *len);
    let mut idx = 0;
    let it = k
        .into_iter()
        .zip(v.into_iter())
        .zip(idx_slice.iter_mut().zip(v_slice.iter_mut()));
    for ((k, v), (i, s)) in it {
        *i = idx;
        *s = v;
        idx += k.len();
        k_slice[..k.len()].copy_from_slice(k.as_bytes());
        k_slice = &mut k_slice[k.len()..];
    }

    PbmxResult::ok()
}
