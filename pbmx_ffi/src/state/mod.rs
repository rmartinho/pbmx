use crate::{keys::PbmxPrivateKey, opaque::Opaque};
use pbmx_kit::state::State;

pub mod chain;
// pub mod secrets;
pub mod vtmf;

pub type Pbmx = Opaque<State>;
ffi_deleter! { pbmx_delete(Pbmx) }

#[no_mangle]
pub unsafe extern "C" fn pbmx_new(sk: PbmxPrivateKey) -> Pbmx {
    Opaque::wrap(State::new(sk.as_ref()?.clone()))
}
