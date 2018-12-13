use std::cell::UnsafeCell;

use rand::{CryptoRng, Error, RngCore};
use rug::rand::{RandGen, RandState};

/// A thread-local RNG bridging the `rand` and `rug` crates
#[derive(Clone, Debug)]
pub struct ThreadRng(*mut RandState<'static>, rand::rngs::ThreadRng);

/// Retrieves this thread's RNG
pub fn thread_rng() -> ThreadRng {
    ThreadRng(THREAD_RAND_STATE.with(|s| s.get()), rand::thread_rng())
}

thread_local! {
    static THREAD_RAND_GEN: UnsafeCell<ThreadRandGen> = UnsafeCell::new(ThreadRandGen);

    static THREAD_RAND_STATE: UnsafeCell<RandState<'static>> =
        UnsafeCell::new(RandState::new_custom(
            // SAFE: pointer is guaranteed dereferenceable thanks to UnsafeCell
            unsafe { &mut *THREAD_RAND_GEN.with(|g| g.get()) },
        ));
}

struct ThreadRandGen;
impl RandGen for ThreadRandGen {
    fn gen(&mut self) -> u32 {
        use rand::Rng;
        rand::thread_rng().gen()
    }
}

impl CryptoRng for ThreadRng {}

impl RngCore for ThreadRng {
    fn next_u32(&mut self) -> u32 {
        self.1.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.1.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.1.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.1.try_fill_bytes(dest)
    }
}
