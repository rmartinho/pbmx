use crate::state::Pbmx;
use libc::{c_int, size_t};
use pbmx_kit::crypto::vtmf::Mask;
use std::slice;

//#[repr(C)]
// pub struct PbmxSecrets {
//    pub(crate) ptr: *mut (Mask, Mask),
//    pub(crate) len: size_t,
//}
//
//#[no_mangle]
// pub unsafe extern "C" fn pbmx_add_secrets(state: Pbmx, secrets: PbmxSecrets)
// -> c_int {    let secrets = slice::from_raw_parts(secrets.ptr, secrets.len);
//    let state = &mut *state.0;
//    if state.add_secrets(secrets.iter().cloned()).is_ok() {
//        1
//    } else {
//        0
//    }
//}
