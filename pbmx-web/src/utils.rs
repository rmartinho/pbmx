use wasm_bindgen::convert::FromWasmAbi;

#[allow(dead_code)]
pub fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub fn vec_from_wasm<T>(slice: &[T::Abi]) -> impl Iterator<Item = T> + '_
where
    T: FromWasmAbi,
    T::Abi: Copy,
{
    slice.iter().map(|u| unsafe { T::from_abi(*u) })
}
