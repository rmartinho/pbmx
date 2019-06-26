use crate::result::PbmxResult;
use libc::{c_char, c_int, c_void, size_t};
use pbmx_kit::crypto::perm::Shuffles;
use rand::{thread_rng, CryptoRng, Rng, RngCore};
use std::slice;

#[repr(C)]
pub struct PbmxForeignRng {
    pub data: *mut c_void,
    pub next_u32: extern "C" fn(*mut c_void) -> u32,
    pub next_u64: extern "C" fn(*mut c_void) -> u64,
    pub fill_bytes: extern "C" fn(*mut c_void, *mut c_char, size_t) -> (),
    pub try_fill_bytes: extern "C" fn(*mut c_void, *mut c_char, size_t) -> c_int,
}

impl RngCore for PbmxForeignRng {
    fn next_u32(&mut self) -> u32 {
        (self.next_u32)(self.data)
    }

    fn next_u64(&mut self) -> u64 {
        (self.next_u64)(self.data)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        (self.fill_bytes)(self.data, dest.as_mut_ptr() as *mut c_char, dest.len());
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        let res = (self.try_fill_bytes)(self.data, dest.as_mut_ptr() as *mut c_char, dest.len());
        if res != 0 {
            Ok(())
        } else {
            Err(rand::Error::new(rand::ErrorKind::Unexpected, "RNG failure"))
        }
    }
}

impl CryptoRng for PbmxForeignRng {}

#[no_mangle]
pub unsafe extern "C" fn pbmx_random_permutation(
    rng: *mut PbmxForeignRng,
    length: size_t,
    perm_out: *mut size_t,
) -> PbmxResult {
    unsafe fn do_random_permutation<R: Rng + CryptoRng>(
        rng: &mut R,
        length: size_t,
        perm_out: *mut size_t,
    ) -> PbmxResult {
        let perm = rng.sample(&Shuffles(length));
        let perm_out = slice::from_raw_parts_mut(perm_out, length);
        perm_out.copy_from_slice(&perm);
        PbmxResult::ok()
    }
    if rng.is_null() {
        do_random_permutation(&mut thread_rng(), length, perm_out)
    } else {
        do_random_permutation(&mut *rng, length, perm_out)
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_random_shift(
    rng: *mut PbmxForeignRng,
    length: size_t,
    k_out: *mut size_t,
) -> PbmxResult {
    unsafe fn do_random_shift<R: Rng + CryptoRng>(
        rng: &mut R,
        length: size_t,
        k_out: *mut size_t,
    ) -> PbmxResult {
        let k = rng.gen_range(0, length);
        k_out.write(k);
        PbmxResult::ok()
    }
    if rng.is_null() {
        do_random_shift(&mut thread_rng(), length, k_out)
    } else {
        do_random_shift(&mut *rng, length, k_out)
    }
}
