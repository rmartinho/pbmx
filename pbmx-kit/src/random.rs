//! Cryptographically strong random number generators

#[cfg(not(target_arch = "wasm32"))]
pub use rand::thread_rng;

#[cfg(target_arch = "wasm32")]
pub use wasm32::thread_rng;

#[cfg(target_arch = "wasm32")]
mod wasm32 {
    use rand::{self, CryptoRng, RngCore};
    use web_sys::window;

    /// WebCrypto-based RNG
    pub fn thread_rng() -> WebCryptoRng {
        WebCryptoRng
    }

    #[derive(Default, Copy, Clone)]
    pub struct WebCryptoRng;

    impl RngCore for WebCryptoRng {
        fn next_u32(&mut self) -> u32 {
            let mut array = [0u8; 4];
            self.fill_bytes(&mut array);
            u32::from_le_bytes(array)
        }

        fn next_u64(&mut self) -> u64 {
            let mut array = [0u8; 8];
            self.fill_bytes(&mut array);
            u64::from_le_bytes(array)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap()
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            let make_err = |_| rand::Error::new("WebCrypto failure");
            window()
                .unwrap()
                .crypto()
                .map_err(make_err)?
                .get_random_values_with_u8_array(dest)
                .map_err(make_err)?;
            Ok(())
        }
    }

    impl CryptoRng for WebCryptoRng {}
}
