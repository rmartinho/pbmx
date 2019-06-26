macro_rules! ffi_deleter {
    ( $fun:ident ( $type:ty ) ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $fun(o: $crate::opaque::Opaque<$type>) {
            o.delete()
        }
    };
}

macro_rules! ffi_serde {
    ($type:ty : $exp:ident $imp:ident) => {
        #[no_mangle]
        pub unsafe extern "C" fn $exp(
            v: $crate::opaque::Opaque<$type>,
            buf: *mut u8,
            len: *mut ::libc::size_t,
        ) -> $crate::result::PbmxResult {
            $crate::serde::ffi_export(v.as_ref()?, buf, len)
        }

        #[no_mangle]
        pub unsafe extern "C" fn $imp(
            buf: *const u8,
            len: ::libc::size_t,
        ) -> $crate::opaque::Opaque<$type> {
            $crate::opaque::Opaque::wrap($crate::serde::ffi_import(buf, len)?)
        }
    };
}
